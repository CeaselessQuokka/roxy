"""Spam detector settings (plan 15.3 E2 and the spam master switches from 15.3 E).

What this is
    The catalog entries for the spam detectors in plan 10.3: the two master switches (`spam_enabled`,
    `spam_dry_run`) and, for each of the seven detectors, six keys: `spam_<id>_enabled`,
    `spam_<id>_threshold`, `spam_<id>_window_s`, `spam_<id>_action`, `spam_<id>_ban_minutes` and
    `spam_<id>_ban_max_minutes`. The detector ids are `rate`, `refused`, `probe`, `auth`, `enum`, `bust`
    and `dist` (the plan's SPAM-RATE, SPAM-REFUSED and so on, lowercased without the prefix).

Why it exists
    Spam detectors look at a client over minutes to hours and can ban it automatically, so every knob must be
    explained well enough that the owner can predict who a change would ban before arming it. Declaring
    the keys here (plan principle P3) gives validation, the settings editor, docs/SETTINGS.md and the LLM
    export one shared description of each detector.

How it works
    The six keys of a detector share their shape, so each detector is described once as a `_Detector`
    record (what it watches, its threshold unit and range, its defaults, and what its "recommend" action
    produces) and `_detector_settings()` turns that record into six `SettingSpec` objects with text that
    names the detector and its real numbers. All keys are in `Group.ABUSE`, apply live, and appear on the
    detector's own sub-card `protection#spam-<id>`; the master switches appear on `protection#spam`.
    No key has `auto_apply_bounds`: auto-apply never touches security settings (plan 11.4).

What to read next
    `roxy/config/settings/throttling.py` (the per-IP limits, bans and bot score these detectors build on),
    plan 10.3, then `roxy/abuse/spam.py`, which evaluates the detectors over sliding windows in hot.db.
"""

from dataclasses import dataclass

from roxy.config.spec import (
    Group,
    OptionSpec,
    Risk,
    RiskCondition,
    RiskOp,
    SettingSpec,
    SettingType,
)

_SPAM_CARD = "protection#spam"

# Each repeat offense inside this many days doubles the previous ban (plan 10.3). A fixed rule, not a setting;
# it is quoted in the help text so the numbers an admin reads match what the detector does.
_REPEAT_WINDOW_DAYS = 30

# The most any spam ban may last: 10080 minutes is 7 days (plan 15.3 E2).
_BAN_MINUTES_MAX = 10080


@dataclass(frozen=True, slots=True)
class _Detector:
    """Everything that differs between two spam detectors; the six settings are generated from it."""

    id: str  # lowercase id used in keys, for example "rate"
    rule_id: str  # plan id, for example "SPAM-RATE"
    name: str  # short human name used in labels
    watches: str  # one or two sentences: what the detector counts and when it fires
    disabled_effect: str  # what is lost when the detector is off
    threshold_type: SettingType
    threshold_default: float
    threshold_min: float
    threshold_max: float
    threshold_step: float
    threshold_unit: str
    threshold_description: str
    threshold_raised: str
    threshold_lowered: str
    window_default: int
    window_raised: str
    window_lowered: str
    action_default: str
    recommend_effect: str  # what the `recommend` action produces for this detector
    ban_minutes: int
    ban_max_minutes: int
    action_ban_risk: str = ""  # non-empty when `ban` is a dangerous action for this detector
    related: tuple[str, ...] = ()  # extra related settings outside the detector's own six keys


# Window text for detectors whose threshold is a COUNT: a longer window gives the same count more time to
# build up, so it catches slower offenders (the opposite of a rate threshold, where a longer window demands
# a longer flood).
_COUNT_WINDOW_RAISED = (
    "The same count can build up over a longer time, so slower offenders are caught too, and a client stays "
    "over the threshold for longer after it stops."
)
_COUNT_WINDOW_LOWERED = (
    "Only offenders that pack the count into a short time are caught; slow, patient ones stay under the threshold."
)

_DETECTORS: tuple[_Detector, ...] = (
    _Detector(
        id="rate",
        rule_id="SPAM-RATE",
        name="Sustained rate",
        watches=(
            "SPAM-RATE watches each client's request rate and fires when it stays far above the per-IP limit "
            "rate for the whole window."
        ),
        disabled_effect=(
            "Clients that keep sending far above their limit are only throttled, never banned, and every one "
            "of their refused requests still costs Roxy work."
        ),
        threshold_type=SettingType.FLOAT,
        threshold_default=5.0,
        threshold_min=1.0,
        threshold_max=100.0,
        threshold_step=0.5,
        threshold_unit="times the per-IP limit rate",
        threshold_description=(
            "SPAM-RATE fires when a client's average request rate over the window is more than this multiple "
            "of the per-IP limit rate. With the default limit of 10 requests per 50 seconds, 5 means more than "
            "about 1 request per second kept up for the whole window (over 600 requests in 10 minutes)."
        ),
        threshold_raised=(
            "Only heavier floods are caught (at 10, about 2 requests per second sustained), with fewer false "
            "positives from busy but legitimate callers."
        ),
        threshold_lowered=(
            "Lighter sustained floods are caught; at 1 or 2, a busy game server that sits just above its limit "
            "can be flagged."
        ),
        window_default=600,
        window_raised=(
            "A flood must last longer before SPAM-RATE fires, because the average is taken over more time; "
            "short bursts are ignored and the signal is steadier."
        ),
        window_lowered=(
            "SPAM-RATE reacts to shorter bursts, so one busy minute from a legitimate caller is more likely to "
            "cross the threshold."
        ),
        action_default="ban",
        recommend_effect="it creates an ABUSE-SPAM recommendation naming the client for you to review.",
        ban_minutes=60,
        ban_max_minutes=10080,
        related=("allowed_requests_per_minute", "throttle_reset_duration", "flood_limit_per_minute"),
    ),
    _Detector(
        id="refused",
        rule_id="SPAM-REFUSED",
        name="Ignored refusals",
        watches=(
            "SPAM-REFUSED counts the requests Roxy refused from each client (throttled, blocked or filtered) "
            "and fires when a client keeps sending anyway."
        ),
        disabled_effect=(
            "Clients that ignore refusals and retry endlessly are never escalated beyond the strike ladder."
        ),
        threshold_type=SettingType.INT,
        threshold_default=200,
        threshold_min=10,
        threshold_max=100000,
        threshold_step=1,
        threshold_unit="refused requests",
        threshold_description=(
            "SPAM-REFUSED fires when more than this many of one client's requests are refused within the "
            "window (by default more than 200 refusals in 10 minutes)."
        ),
        threshold_raised=(
            "Clients may ignore more refusals before the detector acts, with fewer false positives from "
            "clients that have clumsy retry logic."
        ),
        threshold_lowered=(
            "Clients that ignore 429s and keep retrying are caught sooner, but a legitimate client with an "
            "aggressive retry loop may be caught too."
        ),
        window_default=600,
        window_raised=_COUNT_WINDOW_RAISED,
        window_lowered=_COUNT_WINDOW_LOWERED,
        action_default="ban",
        recommend_effect="it creates an ABUSE-SPAM recommendation naming the client for you to review.",
        ban_minutes=30,
        ban_max_minutes=1440,
        related=("throttle_strike_on_retry", "tarpit_on_spam"),
    ),
    _Detector(
        id="probe",
        rule_id="SPAM-PROBE",
        name="Probing",
        watches=(
            "SPAM-PROBE counts probe requests from each client: requests no Roblox client sends, such as paths "
            "like .env or wp-login, unsafe characters, or URLs that are not Roblox hosts."
        ),
        disabled_effect="Scanners looking for weaknesses are only logged and never banned automatically.",
        threshold_type=SettingType.INT,
        threshold_default=5,
        threshold_min=1,
        threshold_max=1000,
        threshold_step=1,
        threshold_unit="probe requests",
        threshold_description=(
            "SPAM-PROBE fires when one client sends at least this many probe requests within the window (by "
            "default 5 probes in 10 minutes)."
        ),
        threshold_raised=(
            "Scanners get more tries before they are banned, with fewer bans for callers who only mistyped a few URLs."
        ),
        threshold_lowered=(
            "Scanners are banned after fewer tries; at 1, a single mistyped URL can get a caller banned."
        ),
        window_default=600,
        window_raised=_COUNT_WINDOW_RAISED,
        window_lowered=_COUNT_WINDOW_LOWERED,
        action_default="ban",
        recommend_effect="it creates an ABUSE-SPAM recommendation naming the client for you to review.",
        ban_minutes=60,
        ban_max_minutes=1440,
        related=("bot_weight_probes", "tarpit_on_probe"),
    ),
    _Detector(
        id="auth",
        rule_id="SPAM-AUTH",
        name="Auth smuggling",
        watches=(
            "SPAM-AUTH counts auth smuggling attempts from each client: requests that try to pass a Roblox "
            "login cookie (.ROBLOSECURITY) or its warning text through Roxy. Roxy always refuses these with "
            "400; this detector bans clients that keep trying."
        ),
        disabled_effect="Clients trying to push account cookies through Roxy are refused each time but never banned.",
        threshold_type=SettingType.INT,
        threshold_default=3,
        threshold_min=1,
        threshold_max=1000,
        threshold_step=1,
        threshold_unit="smuggling attempts",
        threshold_description=(
            "SPAM-AUTH fires when one client makes at least this many auth smuggling attempts within the "
            "window (by default 3 in one hour)."
        ),
        threshold_raised="Clients get more refused login attempts before a ban.",
        threshold_lowered=(
            "Clients sending account cookies are banned after fewer attempts; at 1, a confused developer "
            "testing once with their own cookie is banned."
        ),
        window_default=3600,
        window_raised=_COUNT_WINDOW_RAISED,
        window_lowered=_COUNT_WINDOW_LOWERED,
        action_default="ban",
        recommend_effect="it creates an ABUSE-SPAM recommendation naming the client for you to review.",
        ban_minutes=60,
        ban_max_minutes=10080,
        related=("tarpit_on_auth_attempt",),
    ),
    _Detector(
        id="enum",
        rule_id="SPAM-ENUM",
        name="Id enumeration",
        watches=(
            "SPAM-ENUM watches for id enumeration: one client requesting a long run of different numeric ids "
            "on one endpoint (for example every user id in turn), which is how scrapers copy Roblox data."
        ),
        disabled_effect=(
            "Scrapers walking through ids meet only the normal limits, and no endpoint rule is suggested."
        ),
        threshold_type=SettingType.INT,
        threshold_default=500,
        threshold_min=10,
        threshold_max=1000000,
        threshold_step=1,
        threshold_unit="distinct ids",
        threshold_description=(
            "SPAM-ENUM fires when one client requests more than this many distinct ids on one endpoint "
            "template within the window (by default more than 500 in 10 minutes)."
        ),
        threshold_raised="Only large enumerations are reported, so games that look up many players are not flagged.",
        threshold_lowered=(
            "Smaller enumerations are reported, with more false positives from games that legitimately look "
            "up many ids."
        ),
        window_default=600,
        window_raised=_COUNT_WINDOW_RAISED,
        window_lowered=_COUNT_WINDOW_LOWERED,
        action_default="recommend",
        recommend_effect=(
            "it creates an ABUSE-SPAM recommendation suggesting an endpoint rate rule for the enumerated endpoint."
        ),
        ban_minutes=0,
        ban_max_minutes=0,
        action_ban_risk=(
            "Games that legitimately look up many different players or items would be banned automatically; "
            "this detector is meant to suggest an endpoint rule instead."
        ),
    ),
    _Detector(
        id="bust",
        rule_id="SPAM-BUST",
        name="Cache busting",
        watches=(
            "SPAM-BUST watches for cache busting: a client adding a query value that changes on almost every "
            "request (a random number or a timestamp), which defeats Roxy's cache and sends every request on "
            "to Roblox."
        ),
        disabled_effect=(
            "Cache busting clients are no longer reported, although the CACHE-KEYSPLIT recommendation can still "
            "spot a busting parameter from cache statistics."
        ),
        threshold_type=SettingType.FLOAT,
        threshold_default=0.9,
        threshold_min=0.5,
        threshold_max=0.99,
        threshold_step=0.01,
        threshold_unit="share of unique values (0 to 1)",
        threshold_description=(
            "SPAM-BUST fires when, over a client's last 200 requests within the window, the share carrying a "
            "query value never seen before is more than this (0.9 means more than 9 in 10 requests)."
        ),
        threshold_raised="Only near-total cache busting is flagged.",
        threshold_lowered=(
            "Clients with naturally varied queries, such as ones that look up many different ids, are flagged too."
        ),
        window_default=600,
        window_raised="Older requests still count toward the 200-request sample, so slower clients are measured too.",
        window_lowered=(
            "Only clients that send their 200 requests within a short time are measured; slower busting is missed."
        ),
        action_default="recommend",
        recommend_effect=(
            "it creates a recommendation to ignore the busting query parameter in cache keys (CACHE-KEYSPLIT) "
            "or to limit the client."
        ),
        ban_minutes=0,
        ban_max_minutes=0,
        action_ban_risk=(
            "Clients with naturally varied queries would be banned automatically; ignoring the busting "
            "parameter fixes the cache without refusing anyone."
        ),
        related=("bot_weight_cache_busting",),
    ),
    _Detector(
        id="dist",
        rule_id="SPAM-DIST",
        name="Distributed burst",
        watches=(
            "SPAM-DIST watches for distributed bursts: many different IPs sending the same User-Agent to one "
            "endpoint at once, the shape of one bot spread over many addresses to dodge per-IP limits."
        ),
        disabled_effect="Attacks spread across many IPs are not reported, and no ABUSE-DIST recommendation is made.",
        threshold_type=SettingType.INT,
        threshold_default=50,
        threshold_min=5,
        threshold_max=100000,
        threshold_step=1,
        threshold_unit="client IPs",
        threshold_description=(
            "SPAM-DIST fires when more than this many different client IPs, all with one User-Agent, together "
            "send over 1,000 requests to one endpoint template within the window (by default more than 50 IPs "
            "in 5 minutes)."
        ),
        threshold_raised="Only larger distributed attacks are reported.",
        threshold_lowered=(
            "Smaller groups are reported; a popular game whose servers all poll one endpoint can look like an "
            "attack, because Roblox game servers share one User-Agent."
        ),
        window_default=300,
        window_raised=_COUNT_WINDOW_RAISED,
        window_lowered=_COUNT_WINDOW_LOWERED,
        action_default="recommend",
        recommend_effect=(
            "it creates an ABUSE-DIST recommendation suggesting a User-Agent rule with global scope, or a "
            "temporary emergency limit (throttle-all)."
        ),
        ban_minutes=0,
        ban_max_minutes=0,
        action_ban_risk=(
            "Every IP in the group would be banned at once. Roblox game servers all send the same User-Agent, "
            "so a popular game polling one endpoint could be cut off on all of its servers."
        ),
        related=("user_agent_rules_enabled",),
    ),
)

DETECTOR_IDS: tuple[str, ...] = tuple(d.id for d in _DETECTORS)


def _human_minutes(minutes: int) -> str:
    """Render a ban length the way an admin thinks of it: 1440 -> '24 hours', 10080 -> '7 days'."""
    if minutes % 1440 == 0:
        days = minutes // 1440
        return f"{days} day" if days == 1 else f"{days} days"
    if minutes % 60 == 0:
        hours = minutes // 60
        return f"{hours} hour" if hours == 1 else f"{hours} hours"
    return f"{minutes} minutes"


def _escalation_example(d: _Detector) -> str:
    """One sentence showing how the default bans of a detector grow, using its real numbers."""
    if d.ban_minutes == 0:
        return f"The default action of {d.rule_id} is recommend, which never bans, so its default ban lengths are 0."
    steps = [d.ban_minutes]
    while steps[-1] * 2 < d.ban_max_minutes and len(steps) < 3:
        steps.append(steps[-1] * 2)
    shown = ", ".join(f"{m} minutes" for m in steps)
    return (
        f"With the defaults a client's bans go {shown}, and so on, up to {d.ban_max_minutes} minutes "
        f"({_human_minutes(d.ban_max_minutes)})."
    )


def _detector_settings(d: _Detector) -> list[SettingSpec]:
    """Turn one detector record into its six settings (plan 15.3 E2 common meanings)."""
    prefix = f"spam_{d.id}"
    own_keys = tuple(
        f"{prefix}_{suffix}"
        for suffix in ("enabled", "threshold", "window_s", "action", "ban_minutes", "ban_max_minutes")
    )
    page = (f"protection#spam-{d.id}",)

    def related(key: str, *extra: str) -> tuple[str, ...]:
        """The detector's other keys, then the shared switches, then anything specific."""
        return (*(k for k in own_keys if k != key), "spam_enabled", "spam_dry_run", *extra, *d.related)

    action_labels = {"ban": "temporary IP ban", "strike": "add a throttle strike", "tarpit": "hold the refusals"}
    default_action_text = action_labels.get(d.action_default, "recommend only")

    enabled = SettingSpec(
        key=f"{prefix}_enabled",
        group=Group.ABUSE,
        label=f"{d.name} detector ({d.rule_id})",
        type=SettingType.BOOL,
        default=1,
        description=f"Turns the {d.rule_id} detector on or off. {d.watches}",
        if_enabled=(
            f"{d.rule_id} checks every client and, when the threshold is crossed, takes its action (by default: "
            f"{default_action_text}). Bans are only logged while dry run is on."
        ),
        if_disabled=d.disabled_effect,
        risk=Risk.LOW,
        related_settings=related(f"{prefix}_enabled"),
        related_recommendations=("ABUSE-SPAM",),
        pages=page,
    )

    threshold = SettingSpec(
        key=f"{prefix}_threshold",
        group=Group.ABUSE,
        label=f"{d.name} threshold",
        type=d.threshold_type,
        default=d.threshold_default,
        unit=d.threshold_unit,
        min=d.threshold_min,
        max=d.threshold_max,
        step=d.threshold_step,
        description=d.threshold_description,
        if_raised=d.threshold_raised,
        if_lowered=d.threshold_lowered,
        risk=Risk.LOW,
        related_settings=related(f"{prefix}_threshold"),
        pages=page,
    )

    window = SettingSpec(
        key=f"{prefix}_window_s",
        group=Group.ABUSE,
        label=f"{d.name} window",
        type=SettingType.DURATION,
        default=d.window_default,
        unit="seconds",
        min=10,
        max=86400,
        step=1,
        description=(
            f"How far back {d.rule_id} looks when it counts requests, in seconds "
            f"(default {d.window_default}, which is {_human_minutes(d.window_default // 60)})."
        ),
        if_raised=d.window_raised,
        if_lowered=d.window_lowered,
        risk=Risk.LOW,
        related_settings=related(f"{prefix}_window_s"),
        pages=page,
    )

    action = SettingSpec(
        key=f"{prefix}_action",
        group=Group.ABUSE,
        label=f"{d.name} action",
        type=SettingType.ENUM,
        default=d.action_default,
        options=(
            OptionSpec(
                "ban",
                "Temporary IP ban",
                f"Bans the client's IP for the first ban length; each repeat offense within {_REPEAT_WINDOW_DAYS} "
                "days doubles the ban, up to the ban cap. While dry run is on this only logs 'would have "
                "banned'. Trusted Roblox game servers get a strike instead, and places are never banned.",
            ),
            OptionSpec(
                "strike",
                "Add a throttle strike",
                "Refuses the offending requests and adds one throttle strike, so the client's next penalties "
                "on the strike ladder are longer. Nobody is banned.",
            ),
            OptionSpec(
                "tarpit",
                "Hold the refusals",
                "Refuses the offending requests after a deliberate delay (the tarpit), so a script that "
                "retries at once is slowed to one attempt per hold. Nobody is banned; the hold uses the "
                "settings on Protection > Tarpit.",
            ),
            OptionSpec(
                "recommend",
                "Recommend only",
                f"Takes no action on traffic; instead {d.recommend_effect}",
            ),
        ),
        description=(
            f"What {d.rule_id} does when a client crosses its threshold. Whatever is chosen, detectors never "
            "ban places (place ids can be forged) and never auto-ban trusted Roblox game servers."
        ),
        risk=Risk.MEDIUM,
        high_risk_if=(RiskCondition(RiskOp.EQ, "ban", d.action_ban_risk),) if d.action_ban_risk else (),
        related_settings=related(
            f"{prefix}_action", "ban_disguise_as_throttle", "roblox_egress_cidrs", "tarpit_on_spam"
        ),
        related_recommendations=("ABUSE-SPAM", "SEC-DEFAULTS") if d.action_ban_risk else ("ABUSE-SPAM",),
        pages=page,
    )

    ban_minutes = SettingSpec(
        key=f"{prefix}_ban_minutes",
        group=Group.ABUSE,
        label=f"{d.name} first ban",
        type=SettingType.INT,
        default=d.ban_minutes,
        unit="minutes",
        min=0,
        max=_BAN_MINUTES_MAX,
        step=1,
        description=(
            f"How long the first automatic ban from {d.rule_id} lasts when its action is ban. Each repeat "
            f"offense within {_REPEAT_WINDOW_DAYS} days doubles the ban, up to the ban cap. 0 means no ban "
            "length is set, which is only valid while the action is not ban."
        ),
        if_raised=(
            "Harsher: offenders stay out longer after a first offense, and a client banned by mistake is "
            "locked out longer too."
        ),
        if_lowered="Lighter: offenders return sooner; repeat offenses still double the ban up to the cap.",
        risk=Risk.LOW,
        related_settings=related(f"{prefix}_ban_minutes"),
        pages=page,
        notes=f"Must not be larger than the ban cap, and must be at least 1 while the action is ban. "
        f"{_escalation_example(d)}",
    )

    ban_max = SettingSpec(
        key=f"{prefix}_ban_max_minutes",
        group=Group.ABUSE,
        label=f"{d.name} ban cap",
        type=SettingType.INT,
        default=d.ban_max_minutes,
        unit="minutes",
        min=0,
        max=_BAN_MINUTES_MAX,
        step=1,
        description=(
            f"The longest a {d.rule_id} ban can grow to. Each repeat offense within {_REPEAT_WINDOW_DAYS} days "
            f"doubles the previous ban until it reaches this cap. {_escalation_example(d)}"
        ),
        if_raised=(
            f"Persistent repeat offenders can be banned for longer, up to {_BAN_MINUTES_MAX} minutes "
            f"({_human_minutes(_BAN_MINUTES_MAX)})."
        ),
        if_lowered="Even persistent offenders return sooner; setting it equal to the first ban turns escalation off.",
        risk=Risk.LOW,
        related_settings=related(f"{prefix}_ban_max_minutes"),
        pages=page,
        notes="Must be at least the first ban length.",
    )

    return [enabled, threshold, window, action, ban_minutes, ban_max]


_MASTER_SWITCHES: list[SettingSpec] = [
    SettingSpec(
        key="spam_enabled",
        group=Group.ABUSE,
        label="Spam detectors",
        type=SettingType.BOOL,
        default=1,
        description=(
            "Master switch for the seven spam detectors, which watch each client over minutes to hours for "
            "sustained abuse: floods, ignored refusals, probing, auth smuggling, id enumeration, cache busting "
            "and distributed bursts. Each detector also has its own switch and action."
        ),
        if_enabled=(
            "Each enabled detector counts its signal and takes its own action when its threshold is crossed "
            "(bans are only logged while dry run is on)."
        ),
        if_disabled=(
            "No detector runs: no automatic bans, no ABUSE-SPAM or ABUSE-DIST evidence, and slow, sustained "
            "abuse only meets the per-IP and flood limits."
        ),
        risk=Risk.MEDIUM,
        related_settings=(
            "spam_dry_run",
            "flood_limit_per_minute",
            "tarpit_on_spam",
            *(f"spam_{d}_enabled" for d in DETECTOR_IDS),
        ),
        related_recommendations=("ABUSE-SPAM", "ABUSE-DIST"),
        pages=(_SPAM_CARD,),
    ),
    SettingSpec(
        key="spam_dry_run",
        group=Group.ABUSE,
        label="Spam detectors dry run",
        type=SettingType.BOOL,
        default=1,
        description=(
            "While dry run is on, a detector whose action is ban only records 'would have banned' and raises an "
            "ABUSE-SPAM recommendation; nobody is actually banned. The other actions (strike, tarpit, "
            "recommend) work normally. Detectors start in dry run so their accuracy can be checked first."
        ),
        if_enabled=(
            "No automatic bans. The Protection page and the recommendations show who would have been banned and why."
        ),
        if_disabled=(
            "Detectors whose action is ban start banning client IPs automatically. Before arming, the dashboard "
            "replays the last 7 days of request samples (FILTER-COLLATERAL) and you must confirm the list of "
            "legitimate-looking clients that would have been banned."
        ),
        risk=Risk.HIGH,
        high_risk_if=(
            RiskCondition(
                RiskOp.EQ,
                0,
                "Arms automatic bans. Many Roblox game servers share IP addresses, so a mis-tuned detector can "
                "cut off many experiences at once, and with an empty Roblox game server IP list real game "
                "servers are not immune.",
            ),
        ),
        related_settings=(
            "spam_enabled",
            "roblox_egress_cidrs",
            "ban_disguise_as_throttle",
            *(f"spam_{d}_action" for d in DETECTOR_IDS),
        ),
        related_recommendations=("ABUSE-SPAM", "FILTER-COLLATERAL", "SEC-DEFAULTS"),
        pages=(_SPAM_CARD,),
    ),
]

SETTINGS: list[SettingSpec] = _MASTER_SWITCHES + [spec for d in _DETECTORS for spec in _detector_settings(d)]
