"""Admin security and session settings (plan 15.3 G): how long admin logins last and how guessing is stopped.

What this is
    The catalog entries for the dashboard's login and session rules: idle and absolute session lifetimes, the
    keepalive heartbeat, the fresh second factor window for sensitive actions, the per-network and global login
    guards, the optional emailed code, trusted devices, the emailed kill-switch link, and the admin network
    allowlist switch.

Why it exists
    v1 hard-coded most of these as constants (`ADMIN_SESSION_IDLE_TIMEOUT`, `MAX_LOGIN_FAILURES`,
    `TRUSTED_DEVICE_DURATION` and so on), so tightening them meant a code change and a deploy. As settings they
    are tunable, validated, audited and visible, and every value that weakens login security is marked high
    risk with the reason, so the SEC-DEFAULTS recommendation can flag it (plan 11.5).

How it works
    `SETTINGS` is a plain list of frozen `SettingSpec` values collected by `roxy/config/catalog.py`. The admin
    auth code (`roxy/admin/auth/`) reads the live values through the runtime settings store on each login or
    session check, so a change applies fleet-wide within about a second. None of these settings has
    `auto_apply_bounds`: the recommendation engine never changes security settings on its own (plan 11.4).
    Owner decision D5 is reflected in the defaults: the authenticator app (TOTP, a 6-digit code that changes
    every 30 seconds) is mandatory and the emailed code is off.

What to read next
    `roxy/config/spec.py` for the field meanings, then `roxy/admin/auth/` (`sessions.py`, `lockout.py`,
    `trusted_devices.py`, `allowlist.py`) for where each value is enforced, and plan sections 9.5 and 9.6.
"""

from __future__ import annotations

from roxy.config.spec import (
    Apply,
    Group,
    Risk,
    RiskCondition,
    RiskOp,
    SettingSpec,
    SettingType,
)

# Plan 15.6: `admin_*`, `two_fa_expiration`, `email_code_digits`, `challenge_expiration`, `trusted_device_days`
# and `invalidation_link_ttl_s` are all edited inline on the Security > Admin access card.
_PAGES: tuple[str, ...] = ("security#admin-access",)

SETTINGS: list[SettingSpec] = [
    # --- Session lifetime ----------------------------------------------------------------------------
    SettingSpec(
        key="admin_session_idle_timeout_s",
        group=Group.ADMIN_SECURITY,
        label="Session idle timeout",
        type=SettingType.DURATION,
        default=900,
        unit="seconds",
        min=60,
        max=86400,
        step=1,
        description=(
            "How long an admin session survives without real use (pointer or keyboard input on the dashboard) "
            "before it ends and you must log in again. An open tab nobody touches does not count as use, so it "
            "still times out."
        ),
        pages=_PAGES,
        if_raised=(
            "Fewer re-logins when you step away, but a session left open on an unattended computer stays usable "
            "for longer."
        ),
        if_lowered="Unattended sessions end sooner, which is safer, but you log in again more often.",
        risk=Risk.MEDIUM,
        high_risk_if=(
            RiskCondition(
                RiskOp.GT,
                14400,
                "A dashboard left open stays logged in through more than 4 hours of inactivity, so anyone at that "
                "computer, or anyone holding a stolen session cookie, can act as admin long after you left.",
            ),
        ),
        apply=Apply.LIVE,
        related_settings=("admin_heartbeat_interval_s", "admin_activity_window_s", "admin_session_max_age_s"),
        related_recommendations=("SEC-DEFAULTS",),
        v1_default=120,
        notes=(
            "Was the v1 constant ADMIN_SESSION_IDLE_TIMEOUT (120 seconds). v2 raises it to 900 because logout and "
            "server-side revocation now really end a session."
        ),
    ),
    SettingSpec(
        key="admin_heartbeat_interval_s",
        group=Group.ADMIN_SECURITY,
        label="Dashboard keepalive interval",
        type=SettingType.DURATION,
        default=30,
        unit="seconds",
        min=5,
        max=300,
        step=1,
        description=(
            "How often an open dashboard tells the server you are still using it (a heartbeat). A heartbeat is sent "
            "only if there was pointer or keyboard input within the activity window, so it keeps busy sessions "
            "alive without keeping idle ones alive."
        ),
        pages=_PAGES,
        if_raised=(
            "Fewer keepalive requests. Keep it well below the idle timeout, or an active session can expire "
            "between two heartbeats."
        ),
        if_lowered="More frequent keepalives (slightly more requests), and your activity is noticed sooner.",
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("admin_session_idle_timeout_s", "admin_activity_window_s"),
        v1_default=10,
        notes=(
            "Was the v1 constant ADMIN_HEARTBEAT_INTERVAL (10 seconds). v1 sent a heartbeat whenever the page was "
            "visible; v2 sends one only after real input. Live updates on the dashboard and automatic refreshes "
            "never extend a session."
        ),
    ),
    SettingSpec(
        key="admin_activity_window_s",
        group=Group.ADMIN_SECURITY,
        label="Activity window",
        type=SettingType.DURATION,
        default=60,
        unit="seconds",
        min=10,
        max=900,
        step=1,
        description=(
            "How recent your last pointer or keyboard input must be for a heartbeat to count as activity. Once you "
            "have not touched the dashboard for this long, heartbeats stop and the idle timeout starts counting."
        ),
        pages=_PAGES,
        if_raised=(
            "An unattended tab keeps the session alive longer after you step away (up to this window plus the idle "
            "timeout)."
        ),
        if_lowered=(
            "Sessions start expiring sooner when you step away; reading a long page without moving the mouse may "
            "count as being away."
        ),
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("admin_heartbeat_interval_s", "admin_session_idle_timeout_s"),
        notes="New in v2.",
    ),
    SettingSpec(
        key="admin_session_max_age_s",
        group=Group.ADMIN_SECURITY,
        label="Maximum session lifetime",
        type=SettingType.DURATION,
        default=43200,
        unit="seconds",
        min=600,
        max=604800,
        step=1,
        description=(
            "The absolute lifetime of an admin session, counted from login, however active you are. After this you "
            "must log in again with your password and second factor. The default is 12 hours."
        ),
        pages=_PAGES,
        if_raised="Fewer forced re-logins, but a stolen session cookie stays usable for longer.",
        if_lowered="More re-logins; a stolen session cookie expires sooner.",
        risk=Risk.MEDIUM,
        high_risk_if=(
            RiskCondition(
                RiskOp.GT,
                86400,
                "A stolen session cookie would stay usable for more than a day, even while it is being used.",
            ),
        ),
        apply=Apply.LIVE,
        related_settings=("admin_session_idle_timeout_s", "admin_reauth_window_s"),
        related_recommendations=("SEC-DEFAULTS",),
        notes="New in v2; v1 sessions had no absolute lifetime.",
    ),
    SettingSpec(
        key="admin_reauth_window_s",
        group=Group.ADMIN_SECURITY,
        label="Fresh second factor window",
        type=SettingType.DURATION,
        default=600,
        unit="seconds",
        min=60,
        max=3600,
        step=1,
        description=(
            "Sensitive actions (replacing the Roblox credential, changing your password, managing passkeys, "
            "factory reset, exporting all data) need a second factor entered within this many seconds. If your "
            "last one is older, the dashboard asks for it again before going ahead."
        ),
        pages=_PAGES,
        if_raised=(
            "Fewer second factor prompts when you do several sensitive actions in a row, but someone using your "
            "unlocked session has longer to do them without being asked."
        ),
        if_lowered="More prompts for sensitive actions, which is safer.",
        risk=Risk.MEDIUM,
        high_risk_if=(
            RiskCondition(
                RiskOp.GT,
                1800,
                "Sensitive actions such as replacing the credential stay possible for over 30 minutes after one "
                "second factor, which gives a hijacked session a long window.",
            ),
        ),
        apply=Apply.LIVE,
        related_settings=("admin_session_max_age_s",),
        related_recommendations=("SEC-DEFAULTS",),
        notes="New in v2. Turning off the credential leak guard is not possible at all, whatever this says.",
    ),
    # --- Login guessing defenses ---------------------------------------------------------------------
    SettingSpec(
        key="admin_login_max_failures",
        group=Group.ADMIN_SECURITY,
        label="Login failures before lockout",
        type=SettingType.INT,
        default=5,
        unit="attempts",
        min=1,
        max=100,
        step=1,
        description=(
            "How many failed logins (wrong password or wrong second factor) are allowed for one username from one "
            "network within the lockout window, before further attempts from that network are refused for a "
            "while. A network here is a block of neighboring addresses (an IPv4 /24, 256 addresses, or an IPv6 "
            "/64), so an attacker cannot dodge the count by changing the last part of their address."
        ),
        pages=_PAGES,
        if_raised="More guesses are allowed before lockout, which makes password guessing cheaper.",
        if_lowered=(
            "Lockout comes sooner; a few typos can lock you out until the window passes (the response says how "
            "many seconds to wait)."
        ),
        risk=Risk.MEDIUM,
        high_risk_if=(
            RiskCondition(
                RiskOp.GT,
                20,
                "More than 20 guesses per network per window makes password guessing much cheaper.",
            ),
        ),
        apply=Apply.LIVE,
        related_settings=("admin_login_window_s", "admin_login_global_max_per_min"),
        related_recommendations=("SEC-DEFAULTS",),
        v1_default=5,
        notes=(
            "Was the v1 constant MAX_LOGIN_FAILURES (5), counted per IP. Failures are counted before the password "
            "is checked, so parallel guesses cannot slip past the limit. Lockout responses are 429 'Too many "
            "attempts; try again in N seconds.'"
        ),
    ),
    SettingSpec(
        key="admin_login_window_s",
        group=Group.ADMIN_SECURITY,
        label="Lockout window",
        type=SettingType.DURATION,
        default=600,
        unit="seconds",
        min=60,
        max=86400,
        step=1,
        description=(
            "The sliding time window in which failed logins are counted for the lockout. Failures older than this "
            "stop counting, so this is also roughly how long a lockout lasts."
        ),
        pages=_PAGES,
        if_raised=(
            "Failures are remembered longer, so a guesser gets fewer tries per hour; a locked-out admin also waits "
            "longer."
        ),
        if_lowered="Failures are forgotten sooner: lockouts are shorter, but a guesser can try more often per hour.",
        risk=Risk.MEDIUM,
        high_risk_if=(
            RiskCondition(
                RiskOp.LT,
                300,
                "Failures are forgotten within a few minutes, so a patient guesser gets many more attempts per hour.",
            ),
        ),
        apply=Apply.LIVE,
        related_settings=("admin_login_max_failures",),
        related_recommendations=("SEC-DEFAULTS",),
        v1_default=600,
        notes="Was the v1 constant LOGIN_FAILURE_WINDOW (600 seconds).",
    ),
    SettingSpec(
        key="admin_login_global_max_per_min",
        group=Group.ADMIN_SECURITY,
        label="Global login attempt limit",
        type=SettingType.INT,
        default=30,
        unit="attempts per minute",
        min=1,
        max=1000,
        step=1,
        description=(
            "A limit on login attempts per minute from all networks together, to stop guessing spread over many "
            "addresses. Above it, attempts are slowed (each waits the global login delay before it is checked), "
            "never refused, so an attacker cannot lock you out. Networks on the admin allowlist and browsers with "
            "a valid trusted device are exempt and do not count."
        ),
        pages=_PAGES,
        if_raised="Weaker defense against distributed guessing: more guesses per minute are checked at full speed.",
        if_lowered=(
            "Slowing engages sooner; during an attack, a real admin on a network that is not exempt may wait a few "
            "seconds per login attempt."
        ),
        risk=Risk.MEDIUM,
        high_risk_if=(
            RiskCondition(
                RiskOp.GT,
                200,
                "More than 200 attempts per minute are checked at full speed, which allows hundreds of thousands of "
                "password guesses per day from many addresses.",
            ),
        ),
        apply=Apply.LIVE,
        related_settings=("admin_login_global_delay_s", "admin_login_max_failures", "admin_allowlist_enabled"),
        related_recommendations=("SEC-DEFAULTS",),
        notes=(
            "New in v2. The alert 'Roxy: login attempts throttled globally' fires when the slowing engages. The "
            "limit is shared by every worker process."
        ),
    ),
    SettingSpec(
        key="admin_login_global_delay_s",
        group=Group.ADMIN_SECURITY,
        label="Global login delay",
        type=SettingType.DURATION,
        default=5,
        unit="seconds",
        min=0,
        max=30,
        step=1,
        description=(
            "While the global login attempt limit is exceeded, each attempt beyond it waits this many seconds "
            "before the password is checked."
        ),
        pages=_PAGES,
        if_raised="Guessing gets slower, and so does logging in for an admin on a network that is not exempt.",
        if_lowered=(
            "Logins are faster during an attack and guessing is cheaper; 0 means the global limit slows nothing."
        ),
        risk=Risk.MEDIUM,
        high_risk_if=(
            RiskCondition(
                RiskOp.LT,
                1,
                "With no delay the global login limit does nothing, so guessing spread over many addresses is not "
                "slowed at all.",
            ),
        ),
        apply=Apply.LIVE,
        related_settings=("admin_login_global_max_per_min",),
        related_recommendations=("SEC-DEFAULTS",),
        notes="New in v2.",
    ),
    # --- Second factor details -----------------------------------------------------------------------
    SettingSpec(
        key="admin_email_code_enabled",
        group=Group.ADMIN_SECURITY,
        label="Allow emailed login codes",
        type=SettingType.BOOL,
        default=0,
        description=(
            "Whether a code sent by email may be used as the second login factor instead of the authenticator app, "
            "a passkey or a recovery code. Email is only as safe as the mailbox, so this is off by default. The "
            "one-time first login after the upgrade from v1 uses an emailed code whatever this says."
        ),
        pages=_PAGES,
        if_enabled=(
            "The login page offers an emailed code. Anyone who can read the admin mailbox and knows the password "
            "can log in, and slow mail can make the code arrive late."
        ),
        if_disabled=(
            "Only the authenticator app, passkeys and recovery codes are accepted as the second factor (recommended)."
        ),
        risk=Risk.HIGH,
        high_risk_if=(
            RiskCondition(
                RiskOp.EQ,
                1,
                "Turns the mailbox into a second factor: anyone who gets into the admin email account and knows "
                "the password can log in.",
            ),
        ),
        apply=Apply.LIVE,
        related_settings=("two_fa_expiration", "email_code_digits", "challenge_expiration"),
        related_recommendations=("SEC-DEFAULTS",),
        notes=(
            "In v1 the emailed code was the only second factor. Owner decision D5: the authenticator app is "
            "mandatory and this stays 0. The upgrade login is a one-time flag on the admin account set by the "
            "migration, not this setting; after it you must enroll an authenticator app and receive 10 recovery "
            "codes."
        ),
    ),
    SettingSpec(
        key="two_fa_expiration",
        group=Group.ADMIN_SECURITY,
        label="Emailed code lifetime",
        type=SettingType.DURATION,
        default=300,
        unit="seconds",
        min=30,
        max=900,
        step=1,
        description=(
            "How long an emailed login code stays valid after it is sent. Used only when emailed codes are allowed, "
            "and for the one-time first login after the upgrade from v1."
        ),
        pages=_PAGES,
        if_raised=(
            "More time for slow email delivery, but a code that leaks (for example in a forwarded mail) can be used "
            "for longer."
        ),
        if_lowered="Codes expire sooner; slow email may arrive after its code is no longer valid.",
        risk=Risk.MEDIUM,
        high_risk_if=(
            RiskCondition(
                RiskOp.GT,
                600,
                "An emailed code stays usable for more than 10 minutes, so a leaked or forwarded code is dangerous "
                "for longer.",
            ),
        ),
        apply=Apply.LIVE,
        related_settings=("admin_email_code_enabled", "email_code_digits", "challenge_expiration"),
        related_recommendations=("SEC-DEFAULTS",),
        v1_default=60,
        notes=(
            "Kept the v1 key name. Never imported from v1 (plan 18.3): the v1 value was tuned for the mandatory "
            "email code, and v2 uses email codes only as an optional fallback. Each code works once."
        ),
    ),
    SettingSpec(
        key="email_code_digits",
        group=Group.ADMIN_SECURITY,
        label="Emailed code length",
        type=SettingType.INT,
        default=16,
        unit="digits",
        min=8,
        max=20,
        step=1,
        description="How many digits an emailed login code has.",
        pages=_PAGES,
        if_raised="Codes are harder to guess but longer to type.",
        if_lowered="Codes are easier to type but easier to guess.",
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("admin_email_code_enabled", "two_fa_expiration"),
        v1_default=16,
        notes="Was the v1 constant TWO_FA_DIGITS (16). The authenticator app always uses 6-digit codes.",
    ),
    SettingSpec(
        key="challenge_expiration",
        group=Group.ADMIN_SECURITY,
        label="Login step time limit",
        type=SettingType.DURATION,
        default=120,
        unit="seconds",
        min=30,
        max=600,
        step=1,
        description=(
            "How long you have between entering your password and entering the second factor. The half-finished "
            "login is tied to your address and browser for this time; after it, you start again from the password."
        ),
        pages=_PAGES,
        if_raised="More time to find your authenticator app or wait for an email.",
        if_lowered="The half-finished login expires sooner, so you may need to re-enter your password more often.",
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("two_fa_expiration", "admin_email_code_enabled"),
        v1_default=60,
        notes=(
            "Kept the v1 key name. In v1 it was the lifetime of the login challenge; in v2 it is the lifetime of the "
            "login transaction. Never imported from v1 because the meaning changed (plan 18.3)."
        ),
    ),
    # --- Trusted devices and the kill-switch link -----------------------------------------------------
    SettingSpec(
        key="admin_trusted_devices_enabled",
        group=Group.ADMIN_SECURITY,
        label="Trusted devices",
        type=SettingType.BOOL,
        default=1,
        description=(
            "Whether you may mark a browser as trusted when you log in, so it skips the second factor prompt for "
            "a number of days. The password is still required every time. Trusted devices are listed on the "
            "Security page, where you can revoke one or all of them."
        ),
        pages=_PAGES,
        if_enabled=(
            "Trusted browsers skip the second factor prompt until their trust expires. A stolen laptop with a "
            "trusted browser needs only your password."
        ),
        if_disabled="Every login asks for the second factor, including from browsers that were trusted earlier.",
        risk=Risk.MEDIUM,
        apply=Apply.LIVE,
        related_settings=("trusted_device_days", "admin_login_global_max_per_min"),
        notes=(
            "New switch in v2; v1 always offered trusted devices for 30 days. Trusted devices are not carried over "
            "from v1 (security reset, plan 18.3)."
        ),
    ),
    SettingSpec(
        key="trusted_device_days",
        group=Group.ADMIN_SECURITY,
        label="Trusted device lifetime",
        type=SettingType.INT,
        default=30,
        unit="days",
        min=1,
        max=90,
        step=1,
        description="How many days a browser marked as trusted may skip the second factor prompt.",
        pages=_PAGES,
        if_raised="Fewer second factor prompts, but a lost or stolen trusted device stays trusted longer.",
        if_lowered=(
            "Trust expires sooner and you enter the second factor more often. To always ask, turn off trusted "
            "devices instead."
        ),
        risk=Risk.MEDIUM,
        high_risk_if=(
            RiskCondition(
                RiskOp.GT,
                60,
                "A lost or stolen device keeps skipping the second factor for more than two months.",
            ),
        ),
        apply=Apply.LIVE,
        related_settings=("admin_trusted_devices_enabled",),
        related_recommendations=("SEC-DEFAULTS",),
        v1_default=30,
        notes="Was the v1 constant TRUSTED_DEVICE_DURATION (30 days, stored in seconds in v1).",
    ),
    SettingSpec(
        key="invalidation_link_ttl_s",
        group=Group.ADMIN_SECURITY,
        label="Kill-switch link lifetime",
        type=SettingType.DURATION,
        default=86400,
        unit="seconds",
        min=600,
        max=604800,
        step=1,
        description=(
            "Every new admin login sends an email with a one-time 'this was not me' link that ends all admin "
            "sessions and can also revoke trusted devices. This is how long that link keeps working."
        ),
        pages=_PAGES,
        if_raised="You can still use the link from an older login email, for example if you read mail late.",
        if_lowered=(
            "Links expire sooner; if you read the login email late the link may no longer work (you can still end "
            "all sessions from the dashboard)."
        ),
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("admin_session_max_age_s",),
        v1_default=86400,
        notes=(
            "Was the v1 constant INVALIDATION_TOKEN_EXPIRATION (86400 seconds). The link is stored only as a hash "
            "and works once: opening it asks for confirmation, and confirming uses it up."
        ),
    ),
    # --- Network allowlist ---------------------------------------------------------------------------
    SettingSpec(
        key="admin_allowlist_enabled",
        group=Group.ADMIN_SECURITY,
        label="Admin network allowlist",
        type=SettingType.BOOL,
        default=0,
        description=(
            "When on, /admin (including the login page) answers only to networks on the admin allowlist; every "
            "other network gets a plain 404 Not Found, as if the dashboard did not exist. The list itself (address "
            "ranges in CIDR form: a base address, a slash, and how many leading bits must match) is edited on the "
            "Security page. Add your networks before turning this on."
        ),
        pages=_PAGES,
        if_enabled=(
            "/admin is hidden from every network that is not listed, which takes it out of attackers' view. If you "
            "log in from a network that is not listed (travel, a new internet provider, mobile data), you are "
            "locked out until the list or this setting is changed from the server console."
        ),
        if_disabled="/admin is reachable from any network, protected by the password, the second factor and lockouts.",
        risk=Risk.MEDIUM,
        apply=Apply.LIVE,
        related_settings=("admin_login_global_max_per_min",),
        related_recommendations=("SEC-ADMIN-ALLOWLIST",),
        notes=(
            "Owner decision D6: off by default. The SEC-ADMIN-ALLOWLIST recommendation proposes turning it on with "
            "the networks you actually log in from. Allowlisted networks are also exempt from the global login "
            "slowdown."
        ),
    ),
]
