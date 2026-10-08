"""Settings group J: the recommendation engine and its auto-apply guardrails.

What this is
    `SETTINGS`, the list of `SettingSpec` declarations for plan 15.3 group J (Insights): whether the
    recommendation engine runs and how often, whether it may apply safe recommendations by itself, the
    guardrails that bound auto-apply, how long recommendations live, and the CRED-PROBE-COST threshold.

Why it exists
    Plan principle P3: every tunable is declared once, with its range, help text, risk and dashboard home, so
    the settings API, editor, generated docs and LLM export can never disagree. The per-rule thresholds
    (`insight_<rule>_*`, group J2) are not here; `roxy/config/catalog.py` generates them from
    `roxy/config/insight_params.py`.

How it works
    Plain data. `roxy/config/catalog.py` imports `SETTINGS`, checks every spec at import time (unique keys,
    valid defaults, text present, no dash characters) and serves them through `CATALOG`. None of these settings
    has `auto_apply_bounds`: auto-apply must never tune its own guardrails or the engine that drives it.

What to read next
    `roxy/config/spec.py` (field meanings), `roxy/config/insight_params.py` (the rule catalog), plan 11.1 to
    11.4 (how the engine evaluates, delivers and auto-applies recommendations).
"""

from roxy.config.spec import Apply, Group, Risk, RiskCondition, RiskOp, SettingSpec, SettingType

_ENGINE = ("recommendations#engine",)

_AUTO_APPLY_KEYS = (
    "insights_auto_apply",
    "auto_apply_max_per_hour",
    "auto_apply_max_step_pct",
    "auto_apply_watch_minutes",
    "auto_apply_rollback_threshold_pct",
)


def _others(key: str, keys: tuple[str, ...]) -> tuple[str, ...]:
    """Every key in `keys` except `key`, for cross links between the auto-apply guardrails."""
    return tuple(k for k in keys if k != key)


SETTINGS: list[SettingSpec] = [
    SettingSpec(
        key="insights_enabled",
        group=Group.INSIGHTS,
        label="Recommendation engine",
        type=SettingType.BOOL,
        default=1,
        description=(
            "Turns the recommendation engine on or off. The engine studies recent traffic, errors and settings and "
            "suggests concrete fixes with evidence on the Recommendations page, for example a longer cache time "
            "for an endpoint Roblox keeps rate-limiting. Health checks and alerts run either way."
        ),
        pages=_ENGINE,
        if_enabled=(
            "Roxy re-checks every rule on a schedule (see the evaluation interval) and right after notable "
            "events such as a burst of Roblox 429s, a circuit breaker opening or a failed health check, then shows "
            "or updates recommendations with the numbers behind them."
        ),
        if_disabled=(
            "No new recommendations are created and auto-apply stops. Existing ones stay visible but are no longer "
            "updated. Health checks and alerts still run, so you still hear about outages, but not about "
            "slow-building problems such as a falling cache hit ratio or a risky setting."
        ),
        risk=Risk.MEDIUM,
        high_risk_if=(),
        apply=Apply.LIVE,
        related_settings=("insights_interval_s", "insights_auto_apply", "recommendation_expiry_days"),
        notes="Also stops the SEC-DEFAULTS rule, which is what points out other settings left at risky values.",
    ),
    SettingSpec(
        key="insights_interval_s",
        group=Group.INSIGHTS,
        label="Evaluation interval",
        type=SettingType.DURATION,
        default=30,
        unit="seconds",
        min=5,
        max=3600,
        step=1,
        description=(
            "How often the leader (the one worker process that runs Roxy's background jobs) re-checks every "
            "recommendation rule on a schedule. Important events, such as a burst of Roblox 429s, a breaker "
            "opening, a settings change or a failed health check, trigger a check right away regardless."
        ),
        pages=_ENGINE,
        if_raised=(
            "Less CPU and fewer database reads on the leader, but slow-building problems (a falling hit ratio, a "
            "growing disk) show up later, up to one interval late."
        ),
        if_lowered=(
            "Recommendations refresh sooner, at the cost of more CPU and database reads on the leader. Very short "
            "intervals add load with little benefit, because most rules look at windows of 10 minutes or more."
        ),
        apply=Apply.LIVE,
        related_settings=("insights_enabled",),
    ),
    SettingSpec(
        key="insights_auto_apply",
        group=Group.INSIGHTS,
        label="Auto-apply safe recommendations",
        type=SettingType.BOOL,
        default=0,
        description=(
            "Lets Roxy apply some recommendations by itself, without an admin clicking Apply. Only "
            "recommendations marked safe for automatic use and low risk qualify, always within the auto-apply "
            "guardrails. It never touches security settings, the credential, the rotator quota, or bans wider "
            "than a single IP address."
        ),
        pages=_ENGINE,
        if_enabled=(
            "Roxy changes its own settings and rules within the guardrails: a limited number of changes per hour, "
            "each moving a value by a limited step. After each change it watches error rate, Roblox 429 rate, "
            "latency and refusals, and rolls the change back automatically if any of them gets worse. Every change "
            "is audited and you are notified."
        ),
        if_disabled=(
            "Recommendations wait for an admin to review and apply them; nothing changes unless a person clicks "
            "Apply. This is the default until you have seen the engine's suggestions are trustworthy."
        ),
        risk=Risk.MEDIUM,
        apply=Apply.LIVE,
        related_settings=("insights_enabled", *_others("insights_auto_apply", _AUTO_APPLY_KEYS)),
        pending_owner_verification=True,
        notes="Owner decision D7 (off by default). Auto-apply never changes its own guardrail settings.",
    ),
    SettingSpec(
        key="auto_apply_max_per_hour",
        group=Group.INSIGHTS,
        label="Auto-applied changes per hour",
        type=SettingType.INT,
        default=3,
        unit="changes per hour",
        min=0,
        max=20,
        step=1,
        description=(
            "The most changes auto-apply may make in any one hour, across all worker processes together. It is a "
            "speed limit on self-tuning, so a person can follow what happened and why."
        ),
        pages=_ENGINE,
        if_raised=(
            "Roxy tunes itself faster, but several changes can land close together, which makes it harder to tell "
            "which one helped or hurt and harder to review afterwards."
        ),
        if_lowered=(
            "Slower self-tuning that is easier to review. At 0 no automatic changes are made even while auto-apply "
            "is on; recommendations still appear for manual review."
        ),
        risk=Risk.MEDIUM,
        apply=Apply.LIVE,
        related_settings=_others("auto_apply_max_per_hour", _AUTO_APPLY_KEYS),
    ),
    SettingSpec(
        key="auto_apply_max_step_pct",
        group=Group.INSIGHTS,
        label="Largest automatic step",
        type=SettingType.PERCENT,
        default=50,
        unit="percent",
        min=5,
        max=200,
        step=1,
        description=(
            "The largest change auto-apply may make to one value in one step, as a percentage of its current "
            "value. At 50, a cache time of 300 seconds can move to at most 450 or down to 150 in one change. Each "
            "setting also has hard bounds of its own that auto-apply never crosses."
        ),
        pages=_ENGINE,
        if_raised=(
            "Bigger automatic jumps reach a good value in fewer steps, but one bad change does more harm before "
            "the watch window catches it. Above 100 a value can more than double in a single step."
        ),
        if_lowered=(
            "Smaller, safer steps; it takes more changes, and so more hours given the hourly limit, to reach the "
            "best value."
        ),
        risk=Risk.MEDIUM,
        high_risk_if=(
            RiskCondition(
                RiskOp.GT,
                100,
                "A single automatic change can more than double a rate limit or cache time before anyone reviews it.",
            ),
        ),
        apply=Apply.LIVE,
        related_settings=_others("auto_apply_max_step_pct", _AUTO_APPLY_KEYS),
        related_recommendations=("SEC-DEFAULTS",),
    ),
    SettingSpec(
        key="auto_apply_watch_minutes",
        group=Group.INSIGHTS,
        label="Watch window after an automatic change",
        type=SettingType.INT,
        default=30,
        unit="minutes",
        min=5,
        max=240,
        step=1,
        description=(
            "After an automatic change, how long Roxy watches the guard metrics (error rate, Roblox 429 rate, p95 "
            "latency, meaning the time 95% of requests finish within, and refused rate) before deciding to keep "
            "the change or roll it back."
        ),
        pages=_ENGINE,
        if_raised=(
            "Decisions rest on more data and are less likely to be fooled by noise, but a harmful change stays in "
            "place longer before it is undone."
        ),
        if_lowered=(
            "Faster decisions on less data: a bad change is undone sooner, but normal traffic swings can cause "
            "needless rollbacks or let a slow-acting problem slip through."
        ),
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=_others("auto_apply_watch_minutes", _AUTO_APPLY_KEYS),
    ),
    SettingSpec(
        key="auto_apply_rollback_threshold_pct",
        group=Group.INSIGHTS,
        label="Rollback threshold",
        type=SettingType.PERCENT,
        default=20,
        unit="percent",
        min=5,
        max=100,
        step=1,
        description=(
            "How much worse any guard metric (error rate, Roblox 429 rate, p95 latency, refused rate) may get "
            "during the watch window, compared with the period just before the change, before Roxy rolls an "
            "automatic change back by itself."
        ),
        pages=_ENGINE,
        if_raised=(
            "Tolerates more regression before rolling back: fewer needless rollbacks, but a harmful change can do "
            "more damage and stay applied."
        ),
        if_lowered=(
            "Rolls back on smaller changes, which may be ordinary noise, so good changes are sometimes undone."
        ),
        risk=Risk.MEDIUM,
        high_risk_if=(
            RiskCondition(
                RiskOp.GT,
                50,
                "An automatic change can make errors or Roblox 429s more than 50% worse and still be kept.",
            ),
        ),
        apply=Apply.LIVE,
        related_settings=_others("auto_apply_rollback_threshold_pct", _AUTO_APPLY_KEYS),
        related_recommendations=("SEC-DEFAULTS",),
    ),
    SettingSpec(
        key="recommendation_expiry_days",
        group=Group.INSIGHTS,
        label="Recommendation expiry",
        type=SettingType.INT,
        default=7,
        unit="days",
        min=1,
        max=90,
        step=1,
        description=(
            "How long an open recommendation stays on the list when nobody acts on it. When it expires it is "
            "closed; if the problem is still there, the engine opens a fresh one with current evidence."
        ),
        pages=_ENGINE,
        if_raised=(
            "Items stay on the list longer, which suits a weekly or slower review habit, but the list can fill up "
            "with items whose evidence is old."
        ),
        if_lowered=(
            "Items expire sooner and re-open with fresh evidence if the problem persists, so the list stays short "
            "but the same issue may re-appear often."
        ),
        apply=Apply.LIVE,
        related_settings=("dismiss_cooldown_days", "retention_recommendations_days"),
    ),
    SettingSpec(
        key="dismiss_cooldown_days",
        group=Group.INSIGHTS,
        label="Quiet period after dismissing",
        type=SettingType.INT,
        default=7,
        unit="days",
        min=0,
        max=365,
        step=1,
        description=(
            "After you dismiss a recommendation, how many days the engine stays quiet about the same issue (the "
            "same rule about the same subject, such as the same endpoint). It re-opens early only if the problem "
            "becomes more severe."
        ),
        pages=_ENGINE,
        if_raised=(
            "Dismissed items stay quiet longer, so fewer repeats, but a problem you dismissed can come back "
            "unnoticed unless its severity rises."
        ),
        if_lowered=(
            "Dismissed items return sooner if the condition is still true. At 0 a dismissed item can re-open at "
            "the next evaluation."
        ),
        apply=Apply.LIVE,
        related_settings=("recommendation_expiry_days",),
    ),
    SettingSpec(
        key="insight_cred_probe_cost_max_per_hour",
        group=Group.INSIGHTS,
        label="Credential self-checks per hour before warning",
        type=SettingType.INT,
        default=6,
        unit="credential calls per hour",
        min=1,
        max=60,
        step=1,
        description=(
            "Threshold for the CRED-PROBE-COST recommendation. If Roxy's own calls that use the Roblox credential "
            "(scheduled liveness probes, health checks, admin-clicked checks) exceed this many in any hour, Roxy "
            "warns that it is spending the account's call budget. At default settings it makes about 2 or 3 such "
            "calls per hour."
        ),
        pages=_ENGINE,
        if_raised=(
            "Tolerates more of Roxy's own credential calls before warning. Every call with the credential counts "
            "against the one Roblox account's rate limit, so keep this close to normal usage."
        ),
        if_lowered="Warns sooner, for example after a few admin-clicked health checks in the same hour.",
        apply=Apply.LIVE,
        related_settings=(
            "credential_probe_interval_min",
            "credential_probe_reserved_per_min",
            "health_auto_interval_h",
            "health_auto_include_credential",
        ),
        related_recommendations=("CRED-PROBE-COST",),
        notes=(
            "This is the only CRED-PROBE-COST threshold, so it is an ordinary setting here rather than a generated "
            "rule parameter (plan 15.3 J2)."
        ),
    ),
]
