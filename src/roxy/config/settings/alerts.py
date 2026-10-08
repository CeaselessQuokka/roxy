"""Alert and email settings (plan 15.3 H): which alerts reach the admin, how often, and through which channel.

What this is
    The catalog entries for alert pacing (`error_email_cooldown`, `email_cooldown`, `alert_rate_limit_per_hour`),
    alert routing (`alert_min_severity`, `alert_webhook_enabled`), the daily digest (`alert_digest_hour`) and
    the scheduled health check that feeds alerts (`health_auto_interval_h`, `health_auto_include_credential`).

Why it exists
    An alert that never arrives hides an outage; an alert that arrives two hundred times hides everything else.
    These settings let the owner pick that balance without a code change. v1 had only the two email cooldowns;
    v2 adds a webhook channel (owner decision D14), a severity filter, a storm cap, a digest and scheduled health
    runs (plan 17.7 and 13.1).

How it works
    `SETTINGS` is a plain list of frozen `SettingSpec` values collected by `roxy/config/catalog.py`. The notifier
    (`roxy/notify/`) reads the live values on every send: each alert carries a cooldown key, and the gap between
    two sends of one key is enforced fleet-wide through the `email_gate` table, so two worker processes never
    both send the same alert (plan C6). The webhook URL itself is a secret held as the systemd credential
    `alert_webhook_url`, never a setting, so nothing here is sensitive.

What to read next
    `roxy/config/spec.py` for the field meanings, then `roxy/notify/` for the alert types and their cooldown keys
    (plan 17.7), and `roxy/health/` for the scheduled health runs.
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

# Plan 15.6: `error_email_cooldown`, `email_cooldown` and `alert_*` live on Settings > Alerts and System > Alerts;
# `health_auto_*` lives on Health > Schedule.
_ALERT_PAGES: tuple[str, ...] = ("settings#alerts", "system#alerts")
_HEALTH_PAGES: tuple[str, ...] = ("health#schedule",)

SETTINGS: list[SettingSpec] = [
    # --- Cooldowns and pacing ------------------------------------------------------------------------
    SettingSpec(
        key="error_email_cooldown",
        group=Group.ALERTS,
        label="Error alert cooldown",
        type=SettingType.DURATION,
        default=300,
        unit="seconds",
        min=30,
        max=86400,
        step=1,
        description=(
            "The minimum time between two alerts about the same Roxy server error (errors with the same "
            "signature, meaning the same kind of failure at the same place in the code), and between two 'all "
            "upstream methods unavailable' alerts. The gap is shared by every worker process, so you get one alert "
            "per gap, not one per process."
        ),
        pages=_ALERT_PAGES,
        if_raised=("Fewer repeated alerts during a long incident, but you may not notice that it is still happening."),
        if_lowered="More alerts, so you get quicker confirmation that a problem continues; noisier during an incident.",
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("email_cooldown", "alert_rate_limit_per_hour", "alert_min_severity"),
        v1_default=300,
        notes=(
            "Kept the v1 key name (the v1 constant was ERROR_EMAIL_COOLDOWN). Imported from v1 only if you had "
            "changed it (plan 18.3). The subjects 'Roxy Error: <signature>' and 'Roxy: all upstream methods "
            "unavailable' are kept from v1 so existing mail filters keep working."
        ),
    ),
    SettingSpec(
        key="email_cooldown",
        group=Group.ALERTS,
        label="Credential alert cooldown",
        type=SettingType.DURATION,
        default=600,
        unit="seconds",
        min=60,
        max=86400,
        step=1,
        description=(
            "The minimum time between two alerts about the Roblox account credential: expired, rejected, or "
            "cooling down because Roblox rate-limited it."
        ),
        pages=_ALERT_PAGES,
        if_raised="Fewer reminders while a credential problem lasts.",
        if_lowered="More frequent reminders until you fix the credential.",
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("error_email_cooldown", "alert_rate_limit_per_hour", "credential_cooldown_default_s"),
        v1_default=600,
        notes=(
            "Kept the v1 key name. In v1 it only spaced out the 'Token Expired' email; v2 uses it for every "
            "credential alert. The 'Token Expired' subject is kept so existing mail filters keep working. Imported "
            "from v1 only if you had changed it (plan 18.3)."
        ),
    ),
    SettingSpec(
        key="alert_rate_limit_per_hour",
        group=Group.ALERTS,
        label="Alert limit per hour",
        type=SettingType.INT,
        default=20,
        unit="messages per channel per hour",
        min=1,
        max=1000,
        step=1,
        description=(
            "The most alert messages Roxy sends to each channel (email, webhook) in one hour. Alerts over the limit "
            "are held back and counted, and the next message that goes out says 'N alerts suppressed'. Credential "
            "leak guard alerts are never held back."
        ),
        pages=_ALERT_PAGES,
        if_raised=(
            "More alerts get through during an alert storm, so your inbox or phone fills faster; very high values "
            "can run into the email provider's daily sending limit."
        ),
        if_lowered=(
            "Storms collapse into an 'N alerts suppressed' summary sooner, so you may see individual alerts late."
        ),
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("alert_min_severity", "error_email_cooldown", "email_cooldown"),
        notes="New in v2. The limit is shared by every worker process.",
    ),
    # --- Routing -------------------------------------------------------------------------------------
    SettingSpec(
        key="alert_min_severity",
        group=Group.ALERTS,
        label="Lowest alert severity sent",
        type=SettingType.ENUM,
        default="warn",
        options=(
            OptionSpec(
                "info",
                "Info and above",
                "Everything, including new admin logins and the daily digest. Noisy, but nothing is filtered out.",
            ),
            OptionSpec(
                "warn",
                "Warnings and above",
                "Anything that may need action soon, such as Roblox rate-limiting Roxy, rising caller errors, a "
                "failed backup, a filling disk or new health check failures, plus everything critical. Recommended.",
            ),
            OptionSpec(
                "critical",
                "Critical only",
                "Only outages, credential leak guard trips, credential rejection and database integrity failures. "
                "Quiet, but you learn about slow problems (such as Roblox rate limiting or a filling disk) late.",
            ),
        ),
        description=(
            "The lowest alert severity sent to any channel; alerts below it are not sent. New admin login emails "
            "are always sent, whatever this says, because they carry the link that ends a session you did not "
            "start."
        ),
        pages=_ALERT_PAGES,
        risk=Risk.MEDIUM,
        high_risk_if=(
            RiskCondition(
                RiskOp.EQ,
                "critical",
                "Slow problems such as Roblox rate limiting, failing backups or a filling disk raise only warnings, "
                "so you would not hear about them until they become outages.",
            ),
        ),
        apply=Apply.LIVE,
        related_settings=("alert_rate_limit_per_hour", "alert_webhook_enabled", "alert_digest_hour"),
        related_recommendations=("SEC-DEFAULTS",),
        notes="New in v2; v1 sent every alert it had.",
    ),
    SettingSpec(
        key="alert_webhook_enabled",
        group=Group.ALERTS,
        label="Send alerts to webhook",
        type=SettingType.BOOL,
        default=0,
        description=(
            "Whether alerts are also posted to a webhook (a web address that turns a post into a chat message, for "
            "example in a Discord channel) as well as emailed. The webhook address is a secret installed on the "
            "server as the credential alert_webhook_url, never typed in here."
        ),
        pages=_ALERT_PAGES,
        if_enabled=(
            "Every alert that passes the severity filter is posted to the webhook as well as emailed, which usually "
            "reaches your phone faster. Turning this on requires the alert_webhook_url credential on the server."
        ),
        if_disabled="Alerts are sent by email only.",
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("alert_min_severity", "alert_rate_limit_per_hour"),
        notes=(
            "Owner decision D14. The 'Send test alert' button on the Settings > Alerts card posts one real "
            "low-severity message, and the H-ALERTS health check tests the channel without sending where it can."
        ),
    ),
    SettingSpec(
        key="alert_digest_hour",
        group=Group.ALERTS,
        label="Daily digest hour",
        type=SettingType.INT,
        default=9,
        unit="hour of day",
        min=-1,
        max=23,
        step=1,
        description=(
            "The hour of the day (0 to 23, in the dashboard time zone) at which Roxy emails a daily digest of open "
            "recommendations, failing health checks and the Roblox rate limiting numbers. -1 turns the digest off."
        ),
        pages=_ALERT_PAGES,
        if_raised="The digest arrives later in the day.",
        if_lowered="The digest arrives earlier in the day; -1 turns it off.",
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("ui_timezone", "alert_min_severity"),
        notes="New in v2. The digest is sent by email only and is an info-level message (plan 17.7).",
    ),
    # --- Scheduled health runs -----------------------------------------------------------------------
    SettingSpec(
        key="health_auto_interval_h",
        group=Group.ALERTS,
        label="Scheduled health check interval",
        type=SettingType.INT,
        default=6,
        unit="hours",
        min=0,
        max=168,
        step=1,
        description=(
            "How often Roxy runs the full proxy health check on its own and alerts you about new failures. 0 turns "
            "scheduled runs off; you can still start a run from the Health page."
        ),
        pages=_HEALTH_PAGES,
        if_raised="Rarer automatic runs, so problems are found later.",
        if_lowered=(
            "More runs and more probe requests to Roblox, which count against the same rate limits as real "
            "traffic; with credential checks included, more calls on the Roblox account too."
        ),
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("health_auto_include_credential", "credential_probe_interval_min", "health_runs_max"),
        related_recommendations=("CRED-PROBE-COST", "SYS-HEALTH-FAIL"),
        notes=(
            "New in v2. Only one worker process (the scheduler leader) starts scheduled runs. CRED-PROBE-COST may "
            "suggest running them less often (a larger interval) to save credential calls."
        ),
    ),
    SettingSpec(
        key="health_auto_include_credential",
        group=Group.ALERTS,
        label="Include credential checks in scheduled runs",
        type=SettingType.BOOL,
        default=0,
        description=(
            "Whether scheduled health runs also run the checks that call Roblox with the account credential (for "
            "example confirming it is still logged in). Runs you start yourself always include them, and the "
            "credential also has its own periodic check (credential_probe_interval_min)."
        ),
        pages=_HEALTH_PAGES,
        if_enabled=(
            "Each scheduled run makes about one more call on the Roblox account, about 4 per day at the default "
            "interval, which counts against the account's call budget."
        ),
        if_disabled=(
            "Scheduled runs skip the checks that call Roblox with the credential, saving the account's call budget "
            "(recommended)."
        ),
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("health_auto_interval_h", "credential_probe_interval_min"),
        related_recommendations=("CRED-PROBE-COST",),
        notes="New in v2 (plan 13.3).",
    ),
]
