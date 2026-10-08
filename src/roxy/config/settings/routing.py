"""Routing and egress settings: which path each upstream call takes, and the rules around those paths.

What this is
    The catalog entries for plan section 15.3 A ("Routing and egress"). Each entry is a `SettingSpec` that says
    what one runtime setting does, its default and range, what happens when it is raised or lowered, how risky
    some values are, and on which dashboard cards it can be edited inline.

Why it exists
    Roxy can reach Roblox three ways (plan 7.1): `direct` (anonymous, from the server's own IP address),
    `credential` (from the server IP with the one Roblox login cookie, allowlisted endpoints only) and `rotator`
    (anonymous, through the paid DataImpulse proxy pool, a different exit IP per session). Most of what makes
    Roxy cheap, safe and kind to Roblox is decided here: how traffic is shared between the free direct path and
    the paid rotator, how rotator sessions behave and what they may cost, which Roblox hosts are reachable at
    all (the SSRF defense), how often a failed call may be retried, and which identity Roxy presents to Roblox.
    Declaring every knob once, with plain-English help, is plan principle P3 (single source of truth).

How it works
    `SETTINGS` is a plain list of frozen `SettingSpec` objects. `roxy/config/catalog.py` collects this list
    with the other groups, checks the whole catalog at import time (unique keys, valid defaults, help text
    present, page anchors present, no dash characters) and serves it to the settings API, the editor, the
    generated docs and the LLM export. Nothing here holds state: the live values sit in `RuntimeSettings`.
    A few defaults that other modules also need (the shipped host allowlist and the two User-Agent strings)
    are exported as module constants so there is exactly one copy of each.

What to read next
    `roxy/config/spec.py` for the field meanings, then `roxy/upstream/routing.py` (the routing decision of
    plan 7.2) and `roxy/egress/rotator.py` (rotator sessions, plan 8.2) to see these values being used.
"""

from __future__ import annotations

from roxy.config.spec import Group, OptionSpec, Risk, RiskCondition, RiskOp, SettingSpec, SettingType

# Dashboard anchors (DESIGN.md section 9, plan 15.6). Every key is also on the Settings page itself.
_ROUTING = "upstream#routing"
_HOSTS = "upstream#hosts"
_ROTATOR = "egress#rotator"
_BUDGET = "egress#budget"

# The shipped host allowlist (plan 9.10 and 15.5), stored as full host names so the SSRF check is a plain
# set membership test after the host has been lowercased and stripped of one trailing dot. The v1 migrator
# unions this list with every roblox.com host seen in v1 data (plan 18.3).
DEFAULT_ALLOWED_ROBLOX_HOSTS: tuple[str, ...] = tuple(
    f"{name}.roblox.com"
    for name in (
        "games",
        "users",
        "thumbnails",
        "groups",
        "catalog",
        "economy",
        "badges",
        "presence",
        "friends",
        "inventory",
        "avatar",
        "apis",
        "develop",
        "accountinformation",
        "accountsettings",
        "premiumfeatures",
        "followings",
        "translations",
        "locale",
        "gamejoin",
        "trades",
        "notifications",
        "points",
        "billing",
        "itemconfiguration",
        "contacts",
        "privatemessages",
        "clientsettings",
        "assetdelivery",
        "auth",
        "search",
        "engagementpayouts",
        "voice",
    )
)

# Decision D23: launch with a browser-like identity (paired with API-shaped request headers in
# `egress/headers.py`) and only switch to the honest identity after the UA experiment has measured both.
DEFAULT_DIRECT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
)

# Placeholder replaced with the env value ROXY_SITE_ORIGIN when the header is built, so the operator's
# address is configured once (in the environment) and never hard-coded here.
SITE_ORIGIN_PLACEHOLDER = "{site_origin}"
DEFAULT_UA_EXPERIMENT_ALT_USER_AGENT = f"Roxy/2 (+{SITE_ORIGIN_PLACEHOLDER})"

# Wording reused by several notes below.
_NEVER_IMPORTED = "The v1 value is never imported because its meaning changed (plan 18.3)."


SETTINGS: list[SettingSpec] = [
    # ------------------------------------------------------------------------------------------------
    # Sharing traffic between the direct path and the rotator (plan 7.2)
    # ------------------------------------------------------------------------------------------------
    SettingSpec(
        key="direct_enabled",
        group=Group.ROUTING,
        label="Direct path enabled",
        type=SettingType.BOOL,
        default=1,
        description=(
            "Allows Roxy to send anonymous requests (without the Roblox login cookie) straight from the server's "
            "own IP address. This direct path is free, and it is the normal way public traffic reaches Roblox."
        ),
        if_enabled=(
            "Anonymous traffic leaves from the server IP, paced by the direct rate bucket. The rotator is used only "
            "when the weights, a routing rule, a direct cooldown or a nearly full direct bucket send traffic there."
        ),
        if_disabled=(
            "Every anonymous request has to go through the paid rotator, so every call costs bandwidth money. If "
            "the rotator is also off, out of budget or cooling down, callers get a 503 (egress_disabled) or a stale "
            "cached copy instead of fresh data."
        ),
        risk=Risk.MEDIUM,
        high_risk_if=(
            RiskCondition(
                RiskOp.EQ,
                0,
                "All anonymous traffic is forced onto the paid rotator, which spends quota on every request, and "
                "if the rotator is unavailable too, Roxy cannot reach Roblox at all.",
            ),
        ),
        related_settings=("rotator_enabled", "direct_weight", "rotator_weight", "direct_bucket_per_min"),
        related_recommendations=("SEC-DEFAULTS",),
        pages=(_ROUTING,),
        notes=(
            "This switch does not affect the credential path, which always leaves from the server IP and is "
            "controlled by credential_enabled."
        ),
    ),
    SettingSpec(
        key="direct_weight",
        group=Group.ROUTING,
        label="Direct path weight",
        type=SettingType.INT,
        default=100,
        min=0,
        max=1000,
        step=1,
        description=(
            "The relative share of anonymous upstream calls sent from the server IP when both the direct path and "
            "the rotator are available. Weights are compared with each other, not read as percentages: direct 300 "
            "and rotator 100 means about three direct calls for every rotator call."
        ),
        if_raised=(
            "A larger share of anonymous traffic leaves from the server IP. That is free, but it concentrates "
            "Roblox's per-IP rate limits on one address."
        ),
        if_lowered=(
            "A larger share goes to the rotator, which is billed per byte. At 0, ordinary traffic goes to the "
            "rotator whenever it is available."
        ),
        risk=Risk.MEDIUM,
        high_risk_if=(
            RiskCondition(
                RiskOp.EQ,
                0,
                "Ordinary anonymous traffic goes to the paid rotator whenever it is available, spending quota on "
                "calls the free direct path could have made.",
            ),
        ),
        related_settings=("rotator_weight", "direct_shift_threshold_pct", "direct_enabled"),
        related_recommendations=("UP-429-HOST", "SEC-DEFAULTS"),
        renamed_from="token_weight",
        v1_default=75,
        pages=(_ROUTING,),
        notes=(
            "In v1 this weight was the share of traffic that carried the operator's login cookie; v2 direct "
            "traffic is anonymous. " + _NEVER_IMPORTED
        ),
    ),
    SettingSpec(
        key="rotator_weight",
        group=Group.ROUTING,
        label="Rotator weight",
        type=SettingType.INT,
        default=0,
        min=0,
        max=1000,
        step=1,
        description=(
            "The relative share of anonymous upstream calls sent through the rotator (DataImpulse, a paid proxy "
            "service that sends calls from many different exit IP addresses) while everything is healthy. The "
            "default 0 makes the rotator a spillover path only: it is used when the direct path is cooling down, "
            "its bucket is nearly full, or a routing rule prefers the rotator."
        ),
        if_raised=(
            "More calls go out through rotator IPs, which spreads load away from the server IP, but each one is "
            "billed by the byte and rotator IPs are often already rate-limited by Roblox."
        ),
        if_lowered="Less rotator spending and more load on the server IP. At 0 the rotator only takes spillover.",
        risk=Risk.MEDIUM,
        related_settings=("direct_weight", "direct_shift_threshold_pct", "rotator_enabled", "rotator_hard_stop_pct"),
        related_recommendations=("UP-429-HOST", "UP-TIMEOUT", "EGR-BURN", "EGR-POOL-BURNED"),
        renamed_from="rotate_weight",
        v1_default=25,
        pages=(_ROUTING, _ROTATOR),
        notes=(
            "Owner decision D13 chose 0 on purpose, so the v1 value of 25 is never imported (plan 18.3). The "
            "monthly hard stop and the daily cap still bound spending whatever this weight is."
        ),
    ),
    SettingSpec(
        key="direct_shift_threshold_pct",
        group=Group.ROUTING,
        label="Direct spillover threshold",
        type=SettingType.PERCENT,
        default=80,
        min=0,
        max=100,
        step=1,
        unit="percent",
        description=(
            "How full the direct path's rate bucket may get before traffic starts moving to the rotator. Above "
            "this fill level the direct weight shifts gradually toward the rotator (only if the rotator is enabled "
            "and within budget), so traffic eases off the server IP before it reaches its pace limit."
        ),
        if_raised=(
            "Spillover starts later: the server IP carries more traffic before any moves to the rotator. That "
            "saves money but lets the direct bucket run closer to full, so more calls wait in the queue."
        ),
        if_lowered=(
            "Spillover starts earlier: traffic moves to the rotator sooner, which keeps the direct bucket emptier "
            "but spends more rotator bytes."
        ),
        related_settings=("direct_weight", "rotator_weight", "direct_bucket_per_min", "direct_bucket_burst"),
        related_recommendations=("EGR-BURN",),
        renamed_from="token_danger_zone",
        v1_default=60,
        pages=(_ROUTING,),
        notes=(
            "Successor of v1's token_danger_zone, which counted requests in the token window instead of measuring "
            "bucket fill. " + _NEVER_IMPORTED
        ),
    ),
    # ------------------------------------------------------------------------------------------------
    # The rotator itself: switch, health, sessions (plans 7.5, 7.11, 8.2)
    # ------------------------------------------------------------------------------------------------
    SettingSpec(
        key="rotator_enabled",
        group=Group.ROUTING,
        label="Rotator enabled",
        type=SettingType.BOOL,
        default=1,
        description=(
            "Master switch for the rotator, the paid DataImpulse proxy pool that sends anonymous requests from many "
            "different exit IP addresses. It only works once a gateway URL is configured on the Egress page or in "
            "the bootstrap credential, and it never carries the Roblox login credential."
        ),
        if_enabled=(
            "The rotator may take anonymous traffic when routing sends it there (a direct cooldown, a direct "
            "bucket above the spillover threshold, a routing rule, or a rotator weight above 0), within the "
            "monthly budget."
        ),
        if_disabled=(
            "No rotator use and no rotator spending. When the direct path is cooling down or saturated, callers get "
            "a stale cached copy or a 429 with Retry-After instead of being served through another IP."
        ),
        related_settings=("rotator_weight", "direct_enabled", "rotator_hard_stop_pct", "rotator_quota_gb_per_month"),
        renamed_from="rotate_enabled",
        v1_default=1,
        pages=(_ROTATOR,),
        notes=(
            "Independently of this switch, a credential leak guard trip disables the egress that tripped it until "
            "an admin re-enables it (plan C2)."
        ),
    ),
    SettingSpec(
        key="rotator_cooldown_s",
        group=Group.ROUTING,
        label="Rotator pause after failures",
        type=SettingType.DURATION,
        default=60,
        min=5,
        max=3600,
        step=1,
        unit="seconds",
        description=(
            "How long the rotator is parked (not used at all) after rotator_max_failures failures in a row. "
            "Failures are connection errors, timeouts, Roblox 429 rate-limit answers and Roblox 5xx server errors "
            "seen through the rotator."
        ),
        if_raised=(
            "A broken or rate-limited pool rests longer before Roxy tries it again, so fewer bytes are wasted on "
            "it, but recovery after a short provider hiccup is slower."
        ),
        if_lowered=(
            "Roxy retries a troubled pool sooner. Brief outages recover faster, but Roxy may keep paying for calls "
            "into a pool that is still failing."
        ),
        related_settings=("rotator_max_failures", "rotator_cooldown_distinct_exits", "rotator_cooldown_window_s"),
        renamed_from="rotate_cooldown",
        v1_default=60,
        pages=(_ROTATOR,),
    ),
    SettingSpec(
        key="rotator_max_failures",
        group=Group.ROUTING,
        label="Rotator failures before pause",
        type=SettingType.INT,
        default=3,
        min=1,
        max=50,
        step=1,
        unit="failures",
        description=(
            "How many consecutive rotator failures park the rotator for rotator_cooldown_s. A failure is a "
            "connection error, a timeout, a Roblox 429 or a Roblox 5xx. In v1 only connection-level failures "
            "counted, so a rate-limited pool was never parked."
        ),
        if_raised=(
            "Longer failure streaks are tolerated, so a flaky pool keeps receiving traffic (and spending bytes) "
            "for longer."
        ),
        if_lowered=(
            "The rotator is parked after fewer failures. That protects the budget but can park a healthy pool "
            "after a short unlucky streak."
        ),
        related_settings=("rotator_cooldown_s",),
        renamed_from="rotate_max_failures",
        v1_default=3,
        pages=(_ROTATOR,),
    ),
    SettingSpec(
        key="rotator_session_mode",
        group=Group.ROUTING,
        label="Rotator session mode",
        type=SettingType.ENUM,
        default="sticky_until_429",
        options=(
            OptionSpec(
                "per_request",
                "New IP every request",
                "Every rotator call gets a fresh exit IP. Works without a session username template, but every "
                "call opens a new connection with its own encryption handshake (about 6 KB and one extra round "
                "trip), so it costs the most bytes.",
            ),
            OptionSpec(
                "sticky",
                "Sticky for a fixed time",
                "Keeps one exit IP for rotator_sticky_seconds, then moves to a new one, even if the old one was "
                "fine. Needs rotator_session_username_template.",
            ),
            OptionSpec(
                "sticky_until_429",
                "Sticky until rate-limited",
                "Keeps one exit IP for as long as it stays healthy and moves to a new one as soon as Roblox answers "
                "it with a 429. Reuses good IPs and drops burned ones. Needs rotator_session_username_template.",
            ),
        ),
        description=(
            "How long Roxy keeps using the same rotator exit IP address. Keeping one (a sticky session) reuses its "
            "connection and saves handshake bytes; switching often spreads calls across more IPs. While "
            "rotator_session_username_template is empty, sticky modes are unavailable and Roxy uses per_request."
        ),
        related_settings=(
            "rotator_session_username_template",
            "rotator_sticky_seconds",
            "rotator_max_sessions",
            "rotator_tls_overhead_bytes",
        ),
        related_recommendations=("EGR-POOL-BURNED", "UP-TIMEOUT"),
        pages=(_ROTATOR,),
        notes=(
            "The H-ROTATOR-SESSION health check verifies that one session id keeps one exit IP and that two "
            "session ids get different IPs."
        ),
    ),
    SettingSpec(
        key="rotator_sticky_seconds",
        group=Group.ROUTING,
        label="Sticky session length",
        type=SettingType.DURATION,
        default=300,
        min=10,
        max=3600,
        step=1,
        unit="seconds",
        description=(
            "How long one rotator exit IP is kept before Roxy moves to a new one. Used only when "
            "rotator_session_mode is sticky and a session username template is set."
        ),
        if_raised=(
            "Fewer new connections and handshakes (fewer bytes), but an exit IP that Roblox has started to limit "
            "stays in use longer."
        ),
        if_lowered="More IP changes, more new connections, and more encryption handshake bytes per hour.",
        related_settings=("rotator_session_mode", "rotator_max_sessions"),
        pages=(_ROTATOR,),
    ),
    SettingSpec(
        key="rotator_country",
        group=Group.ROUTING,
        label="Rotator exit country",
        type=SettingType.STRING,
        default="",
        max_length=2,
        description=(
            "Optional two-letter country code (ISO 3166-1, for example US or DE) that limits rotator exit IPs to "
            "one country. Empty uses exits in any country, which is the largest pool."
        ),
        related_settings=("rotator_session_username_template",),
        pages=(_ROTATOR,),
        notes=(
            "A country code means a smaller pool, which may see more 429s and higher latency. The code reaches the "
            "provider through the {country} placeholder of rotator_session_username_template, so it only takes "
            "effect when the template uses that placeholder."
        ),
    ),
    SettingSpec(
        key="rotator_session_username_template",
        group=Group.ROUTING,
        label="Rotator session username template",
        type=SettingType.STRING,
        default="",
        max_length=200,
        description=(
            "The pattern used to build the DataImpulse proxy username for one sticky session: {user} becomes the "
            "username from the stored gateway URL, {session} becomes Roxy's random session id, and {country} "
            "becomes rotator_country. Empty means sticky sessions are unavailable and every rotator call uses a "
            "new IP."
        ),
        risk=Risk.MEDIUM,
        related_settings=("rotator_session_mode", "rotator_country", "rotator_sticky_seconds"),
        pages=(_ROTATOR,),
        pending_owner_verification=True,
        notes=(
            "PENDING owner verification: the syntax is defined by DataImpulse, so Roxy ships no guess. Check the "
            "provider's documentation and fill it in; the shape is something like {user}__sessid-{session}, but "
            "that is only an example. Always use the {user} placeholder and never type the real username or "
            "password here. A wrong template makes the gateway reject rotator calls, which parks the rotator; the "
            "H-ROTATOR-SESSION health check confirms a new template works."
        ),
    ),
    SettingSpec(
        key="rotator_max_sessions",
        group=Group.ROUTING,
        label="Warm rotator sessions per worker",
        type=SettingType.INT,
        default=16,
        min=1,
        max=256,
        step=1,
        unit="sessions",
        description=(
            "How many sticky rotator sessions each worker process keeps open at once. Each session needs its own "
            "proxy connection pool, so Roxy keeps the most recently used ones and closes the oldest when the cap is "
            "reached. The cap is per worker: the server holds up to this number times the worker count."
        ),
        if_raised=(
            "More exit IPs stay warm and reusable, at the cost of more open sockets and memory in every worker, "
            "and the production server has little memory to spare."
        ),
        if_lowered="Sessions are closed and reopened more often: more handshakes, more bytes, more exit IP changes.",
        related_settings=("rotator_session_mode", "rotator_sticky_seconds"),
        pages=(_ROTATOR,),
    ),
    SettingSpec(
        key="rotator_cooldown_distinct_exits",
        group=Group.ROUTING,
        label="Rate-limited exits before endpoint pause",
        type=SettingType.INT,
        default=3,
        min=1,
        max=20,
        step=1,
        unit="exits",
        description=(
            "How many different rotator exit IPs must get a Roblox 429 on the same endpoint within "
            "rotator_cooldown_window_s before Roxy stops using the rotator for that endpoint until the cooldown "
            "ends. A single 429 only swaps that session for a new exit, because one burned IP says little about "
            "the rest of the pool."
        ),
        if_raised=(
            "The rotator keeps trying a rate-limited endpoint through more exits before pausing, which wastes more "
            "bytes when Roblox is limiting the endpoint itself rather than one IP."
        ),
        if_lowered=(
            "One or two burned exits pause the endpoint on the rotator sooner. At 1, any single 429 pauses it, "
            "which can idle a mostly healthy pool."
        ),
        related_settings=("rotator_cooldown_window_s", "rotator_cooldown_s", "cooldown_default_s"),
        pages=(_ROTATOR,),
        notes="The rotator circuit breaker counts failures with the same distinct exit rule (plan 7.10).",
    ),
    SettingSpec(
        key="rotator_cooldown_window_s",
        group=Group.ROUTING,
        label="Rate-limited exits window",
        type=SettingType.DURATION,
        default=60,
        min=10,
        max=3600,
        step=1,
        unit="seconds",
        description=(
            "The time window in which the 429s from different exits, counted by rotator_cooldown_distinct_exits, "
            "must arrive to pause an endpoint on the rotator."
        ),
        if_raised=(
            "429s spread over a longer time still add up to a pause, so slow but steady rate limiting is caught "
            "and the endpoint is paused more often."
        ),
        if_lowered=(
            "Only 429s close together count, so the rotator keeps trying an endpoint that is rate-limited at a "
            "slow, steady pace, wasting more bytes."
        ),
        related_settings=("rotator_cooldown_distinct_exits", "rotator_cooldown_s"),
        pages=(_ROTATOR,),
    ),
    # ------------------------------------------------------------------------------------------------
    # Rotator budget and metering (plans 8.3, 8.4)
    # ------------------------------------------------------------------------------------------------
    SettingSpec(
        key="rotator_quota_gb_per_month",
        group=Group.ROUTING,
        label="Rotator monthly quota",
        type=SettingType.FLOAT,
        default=0.0,
        min=0,
        max=100000,
        step=0.1,
        unit="GB",
        description=(
            "The data allowance of your DataImpulse plan per billing cycle, in gigabytes. Roxy uses it for budget "
            "alerts, the usage projection and the hard stop. 0 means unknown: bytes are still metered, but no "
            "percentage alert or hard stop can fire."
        ),
        if_raised="Percentage alerts and the hard stop fire later, at larger byte totals.",
        if_lowered="Percentage alerts and the hard stop fire earlier, at smaller byte totals.",
        risk=Risk.MEDIUM,
        related_settings=(
            "rotator_budget_alert_pcts",
            "rotator_hard_stop_pct",
            "rotator_billing_day",
            "rotator_price_per_gb_usd",
            "rotator_daily_cap_mb",
        ),
        pages=(_ROTATOR, _BUDGET),
        notes=(
            "Fill this in from your DataImpulse plan (owner decision D12). Automatic recommendation changes never "
            "touch the quota (plan 11.4)."
        ),
    ),
    SettingSpec(
        key="rotator_price_per_gb_usd",
        group=Group.ROUTING,
        label="Rotator price per GB",
        type=SettingType.FLOAT,
        default=0.0,
        min=0,
        max=100,
        step=0.01,
        unit="USD per GB",
        description=(
            "What DataImpulse charges per gigabyte, in US dollars. It is used only to show cost so far and "
            "projected cost on the Egress page and never changes routing. 0 means unknown, so projections show "
            "bytes only."
        ),
        if_raised="Higher cost-so-far and projected cost figures.",
        if_lowered="Lower cost-so-far and projected cost figures.",
        related_settings=("rotator_quota_gb_per_month",),
        pages=(_ROTATOR, _BUDGET),
        notes="Fill this in from your DataImpulse plan (owner decision D12).",
    ),
    SettingSpec(
        key="rotator_billing_day",
        group=Group.ROUTING,
        label="Billing cycle start day",
        type=SettingType.INT,
        default=1,
        min=1,
        max=28,
        step=1,
        unit="day of month",
        description=(
            "The day of the month your DataImpulse plan resets. Roxy starts a new usage cycle on this day, which "
            "resets the cycle totals, the budget alerts and the hard stop. The range ends at 28 so the day exists "
            "in every month."
        ),
        if_raised=(
            "The cycle boundary moves later in the month. Match it to the provider's real reset day so cycle "
            "totals line up with the bill."
        ),
        if_lowered=(
            "The cycle boundary moves earlier in the month. A mismatch with the provider's reset day makes cycle "
            "totals, alerts and the hard stop disagree with the bill."
        ),
        related_settings=("rotator_quota_gb_per_month", "rotator_hard_stop_pct"),
        pages=(_ROTATOR, _BUDGET),
    ),
    SettingSpec(
        key="rotator_budget_alert_pcts",
        group=Group.ROUTING,
        label="Budget alert thresholds",
        type=SettingType.LIST_INT,
        default=[50, 80, 95],
        max_length=10,
        item_min=1,
        item_max=100,
        unit="percent of quota",
        description=(
            "Shares of the monthly quota at which Roxy alerts the admin as rotator usage grows during a billing "
            "cycle. They need rotator_quota_gb_per_month to be set."
        ),
        if_raised="Alerts arrive later in the cycle, leaving less time to react before the quota runs out.",
        if_lowered="Alerts arrive earlier, giving more warning before the quota runs out.",
        related_settings=("rotator_quota_gb_per_month", "rotator_hard_stop_pct"),
        pages=(_ROTATOR, _BUDGET),
    ),
    SettingSpec(
        key="rotator_hard_stop_pct",
        group=Group.ROUTING,
        label="Rotator hard stop",
        type=SettingType.PERCENT,
        default=100,
        min=0,
        max=200,
        step=1,
        unit="percent of quota",
        description=(
            "When rotator usage in the current billing cycle reaches this share of rotator_quota_gb_per_month, "
            "Roxy stops using the rotator until the next cycle and sends anonymous traffic direct only. 0 means "
            "never stop. It only works when the quota is set."
        ),
        if_raised=(
            "Rotator use continues further into the quota; above 100 it continues past the plan's allowance, which "
            "may mean overage charges or a provider cutoff."
        ),
        if_lowered=(
            "The rotator stops earlier in the cycle, keeping some quota unused but losing the spillover path for "
            "the rest of the cycle sooner."
        ),
        risk=Risk.MEDIUM,
        high_risk_if=(
            RiskCondition(
                RiskOp.EQ,
                0,
                "Rotator spending is never stopped automatically, so a traffic spike can use up the whole quota "
                "and keep paying.",
            ),
            RiskCondition(
                RiskOp.GT,
                100,
                "Roxy keeps using the rotator after the plan's quota is used up, which can mean overage charges.",
            ),
        ),
        related_settings=("rotator_quota_gb_per_month", "rotator_daily_cap_mb", "rotator_budget_alert_pcts"),
        related_recommendations=("SEC-DEFAULTS",),
        pages=(_ROTATOR, _BUDGET),
    ),
    SettingSpec(
        key="rotator_daily_cap_mb",
        group=Group.ROUTING,
        label="Rotator daily cap",
        type=SettingType.INT,
        default=0,
        min=0,
        max=1000000,
        step=1,
        unit="MB",
        description=(
            "The most rotator data Roxy may use in one day, in megabytes. When it is reached, Roxy stops using the "
            "rotator until the next day. 0 means no daily cap, so only the monthly hard stop applies."
        ),
        if_raised="More rotator data per day; one busy day can use a larger part of the monthly quota.",
        if_lowered=(
            "Spending is spread more evenly across the cycle, but on busy days the spillover path closes earlier."
        ),
        related_settings=("rotator_hard_stop_pct", "rotator_quota_gb_per_month"),
        related_recommendations=("EGR-BURN",),
        pages=(_ROTATOR, _BUDGET),
    ),
    SettingSpec(
        key="rotator_tls_overhead_bytes",
        group=Group.ROUTING,
        label="Handshake bytes per new rotator connection",
        type=SettingType.BYTES,
        default=6000,
        min=0,
        max=50000,
        step=100,
        unit="bytes",
        description=(
            "The assumed extra bytes the encryption handshake (TLS) costs each time the rotator opens a new "
            "connection. It is used only by the fallback byte estimate, when the exact socket-level meter is "
            "unavailable; the Egress page shows which method is active."
        ),
        if_raised=(
            "Estimated rotator usage goes up, so alerts, the daily cap and the hard stop fire sooner (only while "
            "the fallback estimate is in use)."
        ),
        if_lowered=(
            "Estimated rotator usage goes down, so alerts and stops fire later and real usage may exceed what Roxy "
            "shows (only while the fallback estimate is in use)."
        ),
        related_settings=("rotator_session_mode", "rotator_quota_gb_per_month"),
        related_recommendations=("EGR-CALIBRATE",),
        pages=(_ROTATOR, _BUDGET),
        notes=(
            "EGR-CALIBRATE suggests a new value when you enter the provider's own usage figure and it differs from "
            "Roxy's estimate by more than 10%."
        ),
    ),
    SettingSpec(
        key="rotator_probe_timeout_s",
        group=Group.ROUTING,
        label="Exit IP check timeout",
        type=SettingType.DURATION,
        default=10,
        min=1,
        max=60,
        step=1,
        unit="seconds",
        description=(
            "How long Roxy waits when it checks which exit IP the rotator is using. The check asks an IP echo "
            "service through the rotator, which is the only way to confirm the IPs really change."
        ),
        if_raised="Waits longer on slow pools before calling the check failed, so the check takes longer.",
        if_lowered="Fails faster, but a slow yet working pool may be reported as failing.",
        related_settings=("rotator_recent_ips",),
        v1_default=10,
        pages=(_ROTATOR,),
        notes="Was the constant ROTATE_PROBE_TIMEOUT in v1.",
    ),
    SettingSpec(
        key="rotator_recent_ips",
        group=Group.ROUTING,
        label="Recent exit IPs kept",
        type=SettingType.INT,
        default=50,
        min=0,
        max=500,
        step=1,
        unit="IPs",
        description=(
            "How many recently seen rotator exit IP addresses Roxy keeps for the Egress page, so you can confirm "
            "the rotator really changes IPs. They are shown masked to /24 by default and are never included in "
            "the LLM export."
        ),
        if_raised="A longer exit IP history to compare, using slightly more storage.",
        if_lowered="A shorter history. At 0, no exit IPs are kept or shown.",
        related_settings=("rotator_probe_timeout_s",),
        v1_default=20,
        pages=(_ROTATOR,),
        notes="Was the constant MAX_ROTATE_IPS in v1.",
    ),
    # ------------------------------------------------------------------------------------------------
    # Which Roblox hosts are reachable at all: the SSRF control (plan 9.10)
    # ------------------------------------------------------------------------------------------------
    SettingSpec(
        key="strict_host_allowlist",
        group=Group.ROUTING,
        label="Strict Roblox host allowlist",
        type=SettingType.BOOL,
        default=1,
        description=(
            "When on, Roxy forwards requests only to the hosts listed in allowed_roblox_hosts. When off, any host "
            "under roblox.com is accepted. Limiting hosts is Roxy's main defense against server-side request "
            "forgery (SSRF: tricking a server into calling places it should not)."
        ),
        if_enabled=(
            'Requests for an unlisted subdomain get 404 "Not a Roblox URL", and the HOST-ADD recommendation '
            "proposes adding a host that real callers keep requesting."
        ),
        if_disabled=(
            "Any roblox.com subdomain is reachable through Roxy, including obscure or internal services you never "
            "meant to expose, which widens the SSRF attack surface."
        ),
        risk=Risk.HIGH,
        high_risk_if=(
            RiskCondition(
                RiskOp.EQ,
                0,
                "Every roblox.com subdomain becomes reachable through Roxy, a much wider attack surface for "
                "server-side request forgery.",
            ),
        ),
        related_settings=("allowed_roblox_hosts",),
        related_recommendations=("SEC-DEFAULTS",),
        pages=(_HOSTS,),
        notes=(
            "Whatever this switch says, Roxy always refuses hosts outside roblox.com, raw IP addresses, ports other "
            "than 443 and URLs with a user name in them (plan 9.10)."
        ),
    ),
    SettingSpec(
        key="allowed_roblox_hosts",
        group=Group.ROUTING,
        label="Allowed Roblox hosts",
        type=SettingType.LIST_STR,
        default=list(DEFAULT_ALLOWED_ROBLOX_HOSTS),
        max_length=200,
        item_max_length=253,
        unit="hosts",
        description=(
            "The Roblox service hosts callers may reach through Roxy, written as full host names such as "
            "games.roblox.com. It is enforced while strict_host_allowlist is on. Every entry must be a roblox.com "
            "subdomain; other domains are always refused."
        ),
        if_raised=(
            "Adding hosts makes more Roblox services reachable. Each added host gives attackers a little more room "
            "for server-side request forgery (SSRF), so add only hosts that real callers need."
        ),
        if_lowered='Callers of a removed host get 404 "Not a Roblox URL".',
        risk=Risk.MEDIUM,
        related_settings=("strict_host_allowlist", "credential_probe_url"),
        related_recommendations=("HOST-ADD",),
        pages=(_HOSTS,),
        notes=(
            "The shipped list is the default from plan 9.10. The v1 migrator adds every roblox.com host seen in v1 "
            "data and reports the additions. HOST-ADD proposals are never applied automatically."
        ),
    ),
    # ------------------------------------------------------------------------------------------------
    # Attempts and timeouts per caller request (plans 7.9, 7.11)
    # ------------------------------------------------------------------------------------------------
    SettingSpec(
        key="upstream_max_attempts",
        group=Group.ROUTING,
        label="Upstream attempts per request",
        type=SettingType.INT,
        default=2,
        min=1,
        max=5,
        step=1,
        unit="attempts",
        description=(
            "The total number of upstream calls Roxy may make for one caller request when Roblox answers with a "
            "5xx server error, times out, or the connection fails. Each retry waits a short random backoff, may "
            "use the other anonymous path, and only happens if the request deadline allows. A 429 (too many "
            "requests) or any other 4xx answer (the request itself was refused) is never retried this way."
        ),
        if_raised=(
            "More resilience against brief Roblox errors, but each failing request can cost Roblox more calls, "
            "adding load exactly when Roblox is struggling."
        ),
        if_lowered=(
            "Fewer upstream calls. At 1 there are no retries, so every brief Roblox error reaches the caller (as a "
            "5xx with Retry-After, or as a stale cached copy when one exists)."
        ),
        risk=Risk.MEDIUM,
        high_risk_if=(
            RiskCondition(
                RiskOp.GTE,
                4,
                "Each failing caller request can cost Roblox 4 or 5 calls during an outage; this kind of retry "
                "amplification helped get v1 rate-limited (plan 2.5, R3).",
            ),
        ),
        related_settings=(
            "request_timeout",
            "fallback_on_429",
            "request_deadline_s",
            "backoff_base_ms",
            "backoff_cap_ms",
        ),
        related_recommendations=("UP-429-AMPLIFY", "SEC-DEFAULTS"),
        auto_apply_bounds=(1, 3),
        renamed_from="max_retries_per_request",
        v1_default=3,
        pages=(_ROUTING,),
        notes=(
            "Wires up v1's max_retries_per_request, which existed but was never read (v1 always allowed up to 3 "
            "method picks through the constant MAX_METHOD_ATTEMPTS). " + _NEVER_IMPORTED
        ),
    ),
    SettingSpec(
        key="fallback_on_429",
        group=Group.ROUTING,
        label="Retry elsewhere after a 429",
        type=SettingType.BOOL,
        default=0,
        description=(
            "When Roblox answers a call with 429 (too many requests), allow exactly one retry through the other "
            "anonymous path (direct or rotator) if that path is healthy. A 429 is never retried onto the "
            "credential path."
        ),
        if_enabled=(
            "Some 429s are recovered by trying another IP, but each recovered request costs Roblox a second call "
            "while it is already limiting Roxy, which can make the limiting last longer."
        ),
        if_disabled=(
            "Strict backoff: a 429 opens a cooldown and the caller gets a stale cached copy or a 429 with "
            "Retry-After. Roblox is not called again for that endpoint and path until the cooldown ends."
        ),
        risk=Risk.MEDIUM,
        high_risk_if=(
            RiskCondition(
                RiskOp.EQ,
                1,
                "Retrying 429s on another IP doubles calls while Roblox is already limiting Roxy; this "
                "cross-path retry was one of the causes of v1's repeated rate limiting (plan 2.5, R3).",
            ),
        ),
        related_settings=("upstream_max_attempts", "rotator_enabled", "direct_enabled"),
        related_recommendations=("UP-429-AMPLIFY", "SEC-DEFAULTS"),
        v1_default=1,
        pages=(_ROUTING,),
        notes="v1 always retried a 429 on the other method with no setting; v2 makes it an explicit opt-in.",
    ),
    SettingSpec(
        key="request_timeout",
        group=Group.ROUTING,
        label="Upstream read timeout",
        type=SettingType.DURATION,
        default=15,
        min=1,
        max=120,
        step=1,
        unit="seconds",
        description=(
            "How long Roxy waits for Roblox to send its response on one upstream attempt before giving up on that "
            "attempt. The overall request deadline (request_deadline_s) still limits all attempts together."
        ),
        if_raised=(
            "Fewer timeouts on slow endpoints, but a stuck call holds the caller and a connection longer, and "
            "fewer retries fit inside the request deadline."
        ),
        if_lowered=(
            "Slow calls fail sooner and free their slots, but endpoints that are slow yet working may start timing out."
        ),
        related_settings=("upstream_connect_timeout_s", "upstream_max_attempts", "request_deadline_s"),
        related_recommendations=("UP-TIMEOUT",),
        auto_apply_bounds=(10, 30),
        v1_default=15,
        pages=(_ROUTING,),
    ),
    SettingSpec(
        key="upstream_connect_timeout_s",
        group=Group.ROUTING,
        label="Upstream connect timeout",
        type=SettingType.DURATION,
        default=5,
        min=1,
        max=30,
        step=1,
        unit="seconds",
        description=(
            "How long Roxy waits to open a network connection for an upstream call before the attempt counts as a "
            "connect failure."
        ),
        if_raised=(
            "Slow or congested networks are tolerated, but an unreachable route takes longer to detect, so the "
            "caller waits longer."
        ),
        if_lowered=(
            "Unreachable routes are detected sooner, but a briefly slow network causes connect failures (a 502 "
            "for the caller once retries run out)."
        ),
        related_settings=("request_timeout", "upstream_max_attempts"),
        pages=(_ROUTING,),
    ),
    # ------------------------------------------------------------------------------------------------
    # The identity Roxy presents to Roblox, and the experiment that chooses it (D23, UP-UA-EXPERIMENT)
    # ------------------------------------------------------------------------------------------------
    SettingSpec(
        key="direct_user_agent",
        group=Group.ROUTING,
        label="Upstream User-Agent",
        type=SettingType.STRING,
        default=DEFAULT_DIRECT_USER_AGENT,
        max_length=200,
        description=(
            "The User-Agent header (the client identity text) Roxy sends to Roblox on the direct and credential "
            "paths. A caller's own User-Agent is never forwarded. The default is a desktop browser identity paired "
            "with API-style request headers (decision D23)."
        ),
        risk=Risk.MEDIUM,
        high_risk_if=(
            RiskCondition(
                RiskOp.EQ,
                "",
                "An empty User-Agent makes upstream calls look like an unidentified script, which rate limiters "
                "often treat more harshly.",
            ),
        ),
        related_settings=("ua_experiment_enabled", "ua_experiment_alt_user_agent"),
        related_recommendations=("UP-UA-EXPERIMENT", "SEC-DEFAULTS"),
        pages=(_ROUTING,),
        notes=(
            "Prefer changing it through the User-Agent experiment rather than by hand: a different identity can "
            "change how strictly Roblox rate-limits the server IP. The honest Roxy/2 identity becomes the default "
            "only after the experiment shows it is not limited more. Rotator sessions use their own consistent "
            "header profiles, not this value."
        ),
    ),
    SettingSpec(
        key="ua_experiment_enabled",
        group=Group.ROUTING,
        label="User-Agent experiment",
        type=SettingType.BOOL,
        default=0,
        description=(
            "Runs a side-by-side (A/B) test on direct traffic: calls are split between direct_user_agent and "
            "ua_experiment_alt_user_agent by a hash of the request's cache key for ua_experiment_days, and the "
            "UP-UA-EXPERIMENT recommendation compares the Roblox 429 rate of each identity."
        ),
        if_enabled=(
            "Part of direct traffic uses the alternative identity. If Roblox limits that identity more, 429s rise "
            "on that part during the experiment; the result comes with a confidence interval and offers the better "
            "identity as the new direct_user_agent."
        ),
        if_disabled="Every direct call uses direct_user_agent and no comparison data is collected.",
        risk=Risk.MEDIUM,
        related_settings=("ua_experiment_days", "ua_experiment_alt_user_agent", "direct_user_agent"),
        related_recommendations=("UP-UA-EXPERIMENT",),
        pages=(_ROUTING,),
    ),
    SettingSpec(
        key="ua_experiment_days",
        group=Group.ROUTING,
        label="User-Agent experiment length",
        type=SettingType.INT,
        default=7,
        min=1,
        max=30,
        step=1,
        unit="days",
        description="How many days the User-Agent experiment runs before UP-UA-EXPERIMENT reports its result.",
        if_raised=(
            "More calls per identity, so a tighter confidence interval and a more trustworthy answer, but it takes "
            "longer."
        ),
        if_lowered=(
            "A faster answer from fewer calls, with a wider interval. The rule reports medium confidence only once "
            "each identity has about 10,000 calls."
        ),
        related_settings=("ua_experiment_enabled",),
        related_recommendations=("UP-UA-EXPERIMENT",),
        pages=(_ROUTING,),
    ),
    SettingSpec(
        key="ua_experiment_alt_user_agent",
        group=Group.ROUTING,
        label="Experiment alternative User-Agent",
        type=SettingType.STRING,
        default=DEFAULT_UA_EXPERIMENT_ALT_USER_AGENT,
        max_length=200,
        description=(
            "The User-Agent tested against direct_user_agent during the experiment. The default is Roxy's honest "
            "identity: {site_origin} is replaced with the public site address (the ROXY_SITE_ORIGIN environment "
            "value) so Roblox can see who is calling and how to reach the operator."
        ),
        related_settings=("ua_experiment_enabled", "direct_user_agent"),
        related_recommendations=("UP-UA-EXPERIMENT",),
        pages=(_ROUTING,),
    ),
]
