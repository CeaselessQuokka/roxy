"""Tarpit settings (plan 15.3 F): how Roxy slows down callers it has already decided to refuse.

What this is
    The catalog entries for every `tarpit_*` runtime setting: the master switch, the random hold length,
    the fleet-wide cap on simultaneous holds and the two clamps on it, the three hold styles (`hold`, `drip`,
    `jitter`) and one on/off switch per refusal category.

Why it exists
    A tarpit is a deliberate delay before sending a refusal (plan 10.6). A fast refusal lets an abusive script
    retry thousands of times; a slow one makes every attempt cost the abuser seconds while costing Roxy only an
    idle task and a connection. v1 showed a `tarpit_on_user_agent_rule` switch in its dashboard that the server
    never defined, so flipping it did nothing. Declaring every category here, once, is what makes that kind of
    drift impossible (plan principle P3).

How it works
    `SETTINGS` is a plain list of frozen `SettingSpec` values. `roxy/config/catalog.py` collects it with the
    other groups, validates it at import time and serves it to the API, the settings editor and the docs.
    `abuse/tarpit.py` reads the live values through the runtime settings store. The cap actually enforced is
    `min(tarpit_max_concurrent, floor(tarpit_connection_budget x tarpit_max_capacity_fraction))`, and
    the cross-field rules (shortest hold <= longest hold, jitter minimum <= jitter maximum, longest hold at most
    `request_deadline_s - 2`) live in `catalog.validate_cross`. The category switches are built by one helper
    so every switch gets the same shape and the same "only while the tarpit is enabled" wording.

What to read next
    `roxy/config/spec.py` for what each field means, then `roxy/abuse/tarpit.py` for how holds are taken as
    leases in hot.db so the cap holds across every worker process (plan C6).
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

# Plan 15.6: every `tarpit_*` key is edited inline on the Protection > Tarpit card.
_PAGES: tuple[str, ...] = ("protection#tarpit",)

# Appended to every category switch description so an admin never wonders why a switch "does nothing".
_ONLY_WHILE_ENABLED = " Only applies while the tarpit master switch is on."


def _category_switch(
    category: str,
    *,
    label: str,
    default: int,
    description: str,
    if_enabled: str,
    if_disabled: str,
    risk: Risk = Risk.LOW,
    related_recommendations: tuple[str, ...] = ("TARPIT-TUNE",),
    extra_related: tuple[str, ...] = (),
    v1_default: int | None = None,
    notes: str = "",
) -> SettingSpec:
    """Build one `tarpit_on_<category>` switch.

    Every category switch shares the group, type, page and the two core related settings; only the text,
    default and risk differ. A helper keeps the eleven switches identical in shape.
    """
    return SettingSpec(
        key=f"tarpit_on_{category}",
        group=Group.TARPIT,
        label=label,
        type=SettingType.BOOL,
        default=default,
        description=description + _ONLY_WHILE_ENABLED,
        pages=_PAGES,
        if_enabled=if_enabled,
        if_disabled=if_disabled,
        risk=risk,
        apply=Apply.LIVE,
        related_settings=("tarpit_enabled", "tarpit_default_type", "tarpit_max_concurrent", *extra_related),
        related_recommendations=related_recommendations,
        v1_default=v1_default,
        notes=notes,
    )


SETTINGS: list[SettingSpec] = [
    # --- Master switch and hold length ---------------------------------------------------------------
    SettingSpec(
        key="tarpit_enabled",
        group=Group.TARPIT,
        label="Tarpit enabled",
        type=SettingType.BOOL,
        default=1,
        description=(
            "Master switch for the tarpit. A tarpit makes a caller that Roxy has already decided to refuse wait "
            "before the refusal is sent, so a script retrying in a loop can only make one attempt per hold. It "
            "never delays a request Roxy serves, and never applies to clients on the bypass list."
        ),
        pages=_PAGES,
        if_enabled=(
            "Refusals in the categories switched on below are held, up to the fleet-wide cap, before they are "
            "sent. Each hold costs Roxy one idle task and one connection and costs the abuser seconds of waiting."
        ),
        if_disabled=(
            "Every refusal is sent instantly, whatever the category switches say. Abusive scripts can retry as "
            "fast as their network allows, which raises load on Roxy and fills the logs faster."
        ),
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("tarpit_default_type", "tarpit_min_seconds", "tarpit_max_seconds", "tarpit_max_concurrent"),
        related_recommendations=("TARPIT-TUNE", "ABUSE-SPAM", "FILTER-ADD"),
        v1_default=1,
        notes=(
            "Fails closed (plan C7): if the shared hold counter in hot.db cannot be read or written, Roxy does not "
            "hold and sends the refusal instantly. The caller always receives the same refusal it would have "
            "received without the tarpit; only the timing changes."
        ),
    ),
    SettingSpec(
        key="tarpit_min_seconds",
        group=Group.TARPIT,
        label="Shortest hold",
        type=SettingType.DURATION,
        default=8,
        unit="seconds",
        min=0,
        max=55,
        step=1,
        description=(
            "The shortest time a held refusal waits before it is sent. Each hold picks a random length between "
            "this and the longest hold, so a script cannot learn the exact delay and set its timeout just below it."
        ),
        pages=_PAGES,
        if_raised=(
            "Every held caller waits at least this long, so abusers lose more time per attempt. Holds last longer, "
            "so more of them overlap and the hold cap is reached sooner (later refusals are then sent instantly)."
        ),
        if_lowered=(
            "Holds can be very short, which weakens the tarpit (at 0 some holds end almost at once). Fewer "
            "connections are tied up at any moment."
        ),
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("tarpit_max_seconds", "tarpit_max_concurrent", "request_deadline_s"),
        related_recommendations=("TARPIT-TUNE",),
        auto_apply_bounds=(2, 15),
        v1_default=8,
        notes=(
            "Must be less than or equal to the longest hold (checked when you save). Imported from v1 only if you "
            "had changed it (plan 18.3)."
        ),
    ),
    SettingSpec(
        key="tarpit_max_seconds",
        group=Group.TARPIT,
        label="Longest hold",
        type=SettingType.DURATION,
        default=20,
        unit="seconds",
        min=1,
        max=55,
        step=1,
        description=(
            "The longest time a held refusal waits before it is sent. Together with the shortest hold it sets the "
            "random range each hold is picked from."
        ),
        pages=_PAGES,
        if_raised=(
            "Abusers wait longer per attempt on average. Each hold keeps its connection open longer, so more holds "
            "overlap and the hold cap fills sooner; refusals beyond the cap are sent instantly and counted as "
            "skipped."
        ),
        if_lowered="Holds end sooner and cost the abuser less time; fewer connections are held at once.",
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("tarpit_min_seconds", "tarpit_max_concurrent", "tarpit_slot_grace_s", "request_deadline_s"),
        related_recommendations=("TARPIT-TUNE",),
        auto_apply_bounds=(5, 40),
        v1_default=20,
        notes=(
            "Must be at least the shortest hold and at most the request deadline minus 2 seconds (checked when you "
            "save). The 55 second ceiling keeps every hold inside the request deadline, so nginx and the server "
            "never time the request out before Roxy sends the refusal. Imported from v1 only if you had changed it."
        ),
    ),
    # --- Fleet-wide cap and its clamps ---------------------------------------------------------------
    SettingSpec(
        key="tarpit_max_concurrent",
        group=Group.TARPIT,
        label="Most holds at once",
        type=SettingType.INT,
        default=50,
        unit="holds",
        min=0,
        max=500,
        step=1,
        description=(
            "The most refusals the whole fleet may hold at the same time, counted across every worker process. "
            "Past this number a refusal is sent instantly and counted as skipped, so the tarpit can never tie up "
            "all of Roxy's connections. The cap actually used can be lower: see the connection budget and the "
            "share of it the tarpit may use."
        ),
        pages=_PAGES,
        if_raised=(
            "More abusive requests can be held at once during a large attack. Holds are cheap (an idle task each), "
            "but every hold uses two nginx connections, one to the caller and one to Roxy."
        ),
        if_lowered=(
            "More refusals skip the tarpit and are sent instantly. 0 stops all holding while leaving the category "
            "switches as they are."
        ),
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("tarpit_max_capacity_fraction", "tarpit_connection_budget", "tarpit_slot_grace_s"),
        related_recommendations=("TARPIT-TUNE",),
        auto_apply_bounds=(10, 200),
        v1_default=6,
        notes=(
            "v1 counted request threads (default 6, at most 64) because a held request occupied a whole thread. "
            "v2 holds are idle async tasks, so the default is 50. Never imported from v1 because the meaning "
            "changed (plan 18.3). The Protection > Tarpit card shows the effective cap and which limit clamped it."
        ),
    ),
    SettingSpec(
        key="tarpit_max_capacity_fraction",
        group=Group.TARPIT,
        label="Share of connection budget the tarpit may use",
        type=SettingType.FLOAT,
        default=0.25,
        unit="fraction",
        min=0.05,
        max=0.5,
        step=0.01,
        description=(
            "A safety clamp on the hold cap, written as a share of the connection budget (0.25 means a quarter). "
            "The cap actually enforced is the smaller of 'Most holds at once' and this share of the connection "
            "budget, rounded down, so a typo in the hold cap cannot let held refusals use up the connections real "
            "callers need."
        ),
        pages=_PAGES,
        if_raised=(
            "Held refusals may use more of the connection budget, leaving less room for real callers while an "
            "attack is being held."
        ),
        if_lowered="The clamp engages sooner: fewer holds at once and more instant refusals.",
        risk=Risk.MEDIUM,
        high_risk_if=(
            RiskCondition(
                RiskOp.GT,
                0.4,
                "More than 40 percent of the connection budget could be tied up by held refusals, so an attack that "
                "triggers many holds can leave too few nginx connections for real callers.",
            ),
        ),
        apply=Apply.LIVE,
        related_settings=("tarpit_connection_budget", "tarpit_max_concurrent"),
        related_recommendations=("TARPIT-TUNE", "SEC-DEFAULTS"),
        v1_default=0.5,
        notes=(
            "Was the v1 constant TARPIT_MAX_CAPACITY_FRACTION (0.5 of the request threads, workers x threads). "
            "v2 holds do not occupy threads, so the scarce resource is nginx connections; the base is now the "
            "connection budget and the default 0.25. With the defaults the clamp allows 1000 holds, so the hold "
            "cap of 50 is what applies."
        ),
    ),
    SettingSpec(
        key="tarpit_connection_budget",
        group=Group.TARPIT,
        label="Connection budget",
        type=SettingType.INT,
        default=4000,
        unit="connections",
        min=100,
        max=100000,
        step=1,
        description=(
            "How many held requests nginx (the web server in front of Roxy) can carry at once, already halved "
            "because every held request uses two nginx connections: one to the caller and one to Roxy. Roxy cannot "
            "read nginx's configuration, so this setting tells it. The default 4000 matches 2 nginx worker "
            "processes with 4096 connections each (8192 connections, halved, rounded down)."
        ),
        pages=_PAGES,
        if_raised=(
            "Allows more holds before the clamp engages. If the number is higher than nginx really supports, held "
            "refusals can use up nginx's connections and real callers are turned away by nginx itself."
        ),
        if_lowered="The clamp engages sooner, so fewer holds and more instant refusals; only the tarpit gets weaker.",
        risk=Risk.MEDIUM,
        apply=Apply.LIVE,
        related_settings=("tarpit_max_capacity_fraction", "tarpit_max_concurrent"),
        related_recommendations=("SYS-HEALTH-FAIL",),
        notes=(
            "Replaces the v1 constant TARPIT_FALLBACK_SLOTS (16) and the thread count it stood in for. The deploy "
            "records the real nginx values in roxy.env (ROXY_NGINX_WORKER_PROCESSES and "
            "ROXY_NGINX_WORKER_CONNECTIONS), and the H-NGINX health check warns when this setting disagrees with "
            "them. Change it here after changing nginx's worker settings."
        ),
    ),
    SettingSpec(
        key="tarpit_slot_grace_s",
        group=Group.TARPIT,
        label="Hold slot grace period",
        type=SettingType.DURATION,
        default=15,
        unit="seconds",
        min=1,
        max=120,
        step=1,
        description=(
            "Each hold takes a slot in a shared counter, and the slot carries an expiry time (a lease) equal to the "
            "hold length plus this grace period. If a worker process dies in the middle of a hold, its slot frees "
            "itself when the lease expires, so a crash can never use up slots permanently."
        ),
        pages=_PAGES,
        if_raised=(
            "Slots of a crashed worker stay taken longer, so after a crash or restart the tarpit has fewer free "
            "slots for a while."
        ),
        if_lowered=(
            "Slots of a crashed worker are reclaimed sooner, but a hold that runs late (for example on a busy "
            "server) can lose its slot early, letting the fleet briefly hold more requests than the cap."
        ),
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("tarpit_max_concurrent", "tarpit_max_seconds"),
        v1_default=15,
        notes="Was the v1 constant TARPIT_SLOT_GRACE (15 seconds).",
    ),
    # --- Hold styles ---------------------------------------------------------------------------------
    SettingSpec(
        key="tarpit_default_type",
        group=Group.TARPIT,
        label="Hold style",
        type=SettingType.ENUM,
        default="hold",
        options=(
            OptionSpec(
                "hold",
                "Hold",
                "Wait a random time between the shortest and longest hold, then send the normal refusal. Costs "
                "Roxy one idle task and one connection per hold; the caller waits the full time. Best for probes "
                "and header rule hits. This is how v1 worked.",
            ),
            OptionSpec(
                "drip",
                "Drip",
                "Send the response headers at once, then the body one byte per drip interval until the hold ends. "
                "Clients that read the body are held for the whole time and some give up and time out. Best for "
                "scrapers that ignore status codes. nginx buffering and compression are switched off for these "
                "responses so the bytes really trickle out.",
            ),
            OptionSpec(
                "jitter",
                "Jitter",
                "Add only a short random delay, between the jitter minimum and maximum, before the refusal. Costs "
                "almost nothing and breaks tight retry loops without holding connections for long. Best for "
                "ordinary rate limit refusals.",
            ),
        ),
        description=(
            "How a held refusal is delayed, for every category that does not use a fixed style of its own (callers "
            "retrying inside their Retry-After always get jitter). Whatever the style, the caller ends up with the "
            "same refusal it would have received instantly."
        ),
        pages=_PAGES,
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=(
            "tarpit_min_seconds",
            "tarpit_max_seconds",
            "tarpit_drip_interval_ms",
            "tarpit_jitter_min_ms",
            "tarpit_jitter_max_ms",
        ),
        related_recommendations=("TARPIT-TUNE",),
        notes="New in v2; v1 always used the hold style.",
    ),
    SettingSpec(
        key="tarpit_drip_interval_ms",
        group=Group.TARPIT,
        label="Drip interval",
        type=SettingType.DURATION,
        default=1000,
        unit="ms",
        min=100,
        max=10000,
        step=1,
        description=(
            "For the drip style: the gap, in milliseconds, between the single bytes of the response body that Roxy "
            "sends while a hold lasts."
        ),
        pages=_PAGES,
        if_raised=(
            "Bytes trickle out more slowly, so Roxy makes fewer tiny writes; a client with a short read timeout is "
            "more likely to give up, which ends its hold early."
        ),
        if_lowered=(
            "Bytes arrive faster, so clients are less likely to time out and stay held for the whole hold; Roxy "
            "makes more tiny writes per held request."
        ),
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("tarpit_default_type", "tarpit_max_seconds"),
        notes="Only used when the hold style is drip.",
    ),
    SettingSpec(
        key="tarpit_jitter_min_ms",
        group=Group.TARPIT,
        label="Jitter minimum delay",
        type=SettingType.DURATION,
        default=500,
        unit="ms",
        min=0,
        max=10000,
        step=1,
        description=(
            "For the jitter style: the shortest random delay, in milliseconds, added before a refusal is sent. "
            "Jitter is used for every held category when the hold style is jitter, and always for callers retrying "
            "inside a Retry-After they were given."
        ),
        pages=_PAGES,
        if_raised="Tight retry loops are slowed more; each refusal keeps its connection a little longer.",
        if_lowered="A lighter touch: refusals go out sooner, and at 0 some get no delay at all.",
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("tarpit_jitter_max_ms", "tarpit_default_type", "tarpit_on_upstream_cooldown_retry"),
        related_recommendations=("UP-RETRYAFTER-IGNORED",),
        notes="Must be less than or equal to the jitter maximum (checked when you save).",
    ),
    SettingSpec(
        key="tarpit_jitter_max_ms",
        group=Group.TARPIT,
        label="Jitter maximum delay",
        type=SettingType.DURATION,
        default=3000,
        unit="ms",
        min=0,
        max=10000,
        step=1,
        description=(
            "For the jitter style: the longest random delay, in milliseconds, added before a refusal is sent. Each "
            "refusal picks a random delay between the jitter minimum and this value."
        ),
        pages=_PAGES,
        if_raised="Tight retry loops are slowed more; sockets are held a little longer per refusal.",
        if_lowered="A lighter effect: refusals go out sooner and retry loops are slowed less.",
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("tarpit_jitter_min_ms", "tarpit_default_type", "tarpit_on_upstream_cooldown_retry"),
        related_recommendations=("UP-RETRYAFTER-IGNORED",),
        notes="Must be at least the jitter minimum (checked when you save).",
    ),
    # --- Per-category switches (which refusals may be held) --------------------------------------------
    _category_switch(
        "header_rule",
        label="Hold header rule refusals",
        default=1,
        description=(
            "Hold refusals caused by a header rule (a request filter you wrote to match traffic by its headers)."
        ),
        if_enabled=(
            "Callers caught by your header rules wait for their refusal. These are almost never real users, "
            "because you wrote the rule to match them."
        ),
        if_disabled="Header rule refusals are sent instantly, so a fingerprinted script can retry at full speed.",
        v1_default=1,
    ),
    _category_switch(
        "probe",
        label="Hold probe refusals",
        default=1,
        description=(
            "Hold refusals for requests that are not valid Roblox API calls at all, such as a URL that is not a "
            "Roblox host or a malformed or unsafe path. This is what vulnerability scanners send; a real caller "
            "never does."
        ),
        if_enabled="Scanners and junk requests wait for their refusal, which slows down automated probing.",
        if_disabled="Probe refusals are sent instantly, so a scanner can try thousands of paths quickly.",
        related_recommendations=("TARPIT-TUNE", "ABUSE-SPAM"),
        v1_default=1,
    ),
    _category_switch(
        "throttle",
        label="Hold per-IP throttle refusals",
        default=0,
        description="Hold refusals from the ordinary per-IP rate limit (requests per window).",
        if_enabled=(
            "Callers over the per-IP limit wait before they hear so. This also catches real users and game servers "
            "that were only a little too fast, so their requests can take seconds longer; the jitter style keeps "
            "that delay short."
        ),
        if_disabled=(
            "Per-IP throttle refusals are sent instantly with Retry-After, which is friendlier to well-behaved callers."
        ),
        risk=Risk.MEDIUM,
        related_recommendations=("TARPIT-TUNE", "FILTER-ADD"),
        extra_related=("allowed_requests_per_minute",),
        v1_default=0,
    ),
    _category_switch(
        "throttle_all",
        label="Hold throttle-all refusals",
        default=0,
        description=(
            "Hold refusals caused by throttle-all, the emergency switch on the top bar that applies a strict limit "
            "to every caller."
        ),
        if_enabled=(
            "During throttle-all, refused callers wait. Throttle-all refuses almost everyone, so holds fill the cap "
            "quickly and real users wait too."
        ),
        if_disabled="Throttle-all refusals are sent instantly.",
        risk=Risk.MEDIUM,
        extra_related=("global_throttle_limit",),
        v1_default=0,
    ),
    _category_switch(
        "endpoint_rule",
        label="Hold endpoint rule refusals",
        default=0,
        description="Hold refusals from per-endpoint rate rules (limits you set on one Roblox endpoint).",
        if_enabled=(
            "Callers over an endpoint limit wait for their refusal. This also catches ordinary callers of a popular "
            "endpoint."
        ),
        if_disabled="Endpoint rule refusals are sent instantly.",
        risk=Risk.MEDIUM,
        v1_default=0,
    ),
    _category_switch(
        "blocked_endpoint",
        label="Hold blocked endpoint refusals",
        default=0,
        description="Hold refusals for requests to an endpoint you blocked.",
        if_enabled=(
            "Callers who keep asking for a blocked endpoint wait. This may hold someone who simply wanted that "
            "endpoint and did not know it is blocked."
        ),
        if_disabled="Blocked endpoint refusals are sent instantly, with the block message you wrote.",
        risk=Risk.MEDIUM,
        v1_default=0,
    ),
    _category_switch(
        "auth_attempt",
        label="Hold credential smuggling refusals",
        default=1,
        description=(
            "Hold refusals for requests that tried to send a Roblox login cookie (.ROBLOSECURITY) or the Roblox "
            "cookie warning text through Roxy. Roxy never forwards these."
        ),
        if_enabled=(
            "Callers trying to push account credentials through Roxy wait for their refusal. A public proxy has no "
            "honest reason to receive a login cookie, so this is on by default in v2."
        ),
        if_disabled=(
            "Smuggling attempts are refused instantly. Occasionally an honest developer pastes a cookie by mistake, "
            "and they get their error faster."
        ),
        related_recommendations=("TARPIT-TUNE", "ABUSE-SPAM"),
        v1_default=0,
        notes="v1 default was 0; v2 turns it on.",
    ),
    _category_switch(
        "user_agent_rule",
        label="Hold User-Agent rule refusals",
        default=0,
        description=(
            "Hold refusals from User-Agent rules (rate rules that match a client by the User-Agent text it sends)."
        ),
        if_enabled=(
            "Callers over a User-Agent rule limit wait. These are usually cooperative bots that would have slowed "
            "down when asked, so holding them mostly punishes clients that would have obeyed anyway."
        ),
        if_disabled="User-Agent rule refusals are sent instantly.",
        risk=Risk.MEDIUM,
        extra_related=("user_agent_rules_enabled",),
        notes=(
            "v1's dashboard showed this switch, but the v1 server rejected the key as unknown, so it never worked "
            "and there is no v1 value to import. In v2 it works."
        ),
    ),
    _category_switch(
        "ban",
        label="Hold refusals for banned clients",
        default=1,
        description="Hold refusals for banned clients, including temporary bans created by the spam detectors.",
        if_enabled=(
            "Banned clients wait for each refusal, so a banned script that keeps retrying makes only one attempt "
            "per hold. When bans are disguised as throttles, the held refusal still looks like an ordinary throttle."
        ),
        if_disabled="Banned clients are refused instantly and can retry as fast as they like (each retry is refused).",
        related_recommendations=("TARPIT-TUNE", "FILTER-ADD"),
        extra_related=("ban_disguise_as_throttle",),
        notes="New in v2.",
    ),
    _category_switch(
        "spam",
        label="Hold spam detector refusals",
        default=1,
        description=(
            "Hold refusals Roxy sends because a spam detector flagged the client, for example a detector whose "
            "action is set to tarpit."
        ),
        if_enabled="Clients flagged by a spam detector wait for each refusal.",
        if_disabled=("Spam refusals are sent instantly, so a detector set to the tarpit action has no delay to apply."),
        related_recommendations=("TARPIT-TUNE", "ABUSE-SPAM"),
        notes="New in v2.",
    ),
    _category_switch(
        "upstream_cooldown_retry",
        label="Jitter early retries during a Roblox cooldown",
        default=0,
        description=(
            "Delay callers who retry the same request before the Retry-After time Roxy gave them, while Roblox has "
            "asked Roxy to back off (a cooldown). This category always uses the short jitter delay, never a full "
            "hold."
        ),
        if_enabled=(
            "Callers that ignore Retry-After get a short random delay on each early retry, which breaks tight retry "
            "loops and lowers load on Roxy. Roblox is not contacted during a cooldown either way, so this does not "
            "reduce Roblox rate limiting."
        ),
        if_disabled="Early retries are refused instantly with the same Retry-After.",
        related_recommendations=("UP-RETRYAFTER-IGNORED", "TARPIT-TUNE"),
        extra_related=("tarpit_jitter_min_ms", "tarpit_jitter_max_ms", "throttle_strike_on_retry"),
        notes="New in v2.",
    ),
]
