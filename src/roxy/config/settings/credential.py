"""Settings catalog content for the Credential group (plan 15.3 B).

What this is
    The `SettingSpec` declarations for every runtime setting that governs Roxy's single Roblox account cookie
    (the "credential"): whether it may be used at all, which endpoints may use it, how fast, how often Roxy
    checks that it still works, and how long Roxy rests the account after Roblox says "slow down" (a 429).

Why it exists
    The credential is the most sensitive thing Roxy holds (plan C1 and C2). Roblox ties rate limits and abuse
    scoring to the account, so these settings keep account use tiny, evenly paced and visible, and every value
    an admin can choose explains what it does to the account before it is saved (plan P3 and 15.1). In v1 the
    account carried 75% of cache misses in unpaced bursts, which plan 2.5 ranks as the top cause of the Roblox
    429s. Decision D1 (revised 2026-10-16) sends it only for endpoints the endpoint policy marks "sent with Roxy's
    account" (`roxy/policy/`), paced by these settings, with an anonymous fallback when the account is busy. The
    three `endpoint_policy_*` settings at the end decide how blocked endpoints are refused.

How it works
    `SETTINGS` is a plain list of frozen `SettingSpec` objects. `roxy/config/catalog.py` collects it with the
    other groups, checks defaults and texts at import time, and serves it to the settings API, the editor, the
    generated docs and the LLM export. Nothing here reads or stores the credential value itself: the value lives
    in the single credential slot (C1), never in a setting, so no spec here is `sensitive`. Rules that span
    two settings (the probe reserve must stay below the credential rate) are checked by
    `catalog.validate_cross`. None of these settings has `auto_apply_bounds`: auto-apply never touches the
    credential (plan 11.4).

What to read next
    `roxy/config/spec.py` (what each field means), `roxy/config/settings/upstream.py` (the global, host and
    endpoint buckets every credential call also passes), then `roxy/egress/credential.py` and
    `roxy/upstream/buckets.py` (where these values are used).
"""

from roxy.config.spec import Apply, Group, OptionSpec, Risk, RiskCondition, RiskOp, SettingSpec, SettingType

# Dashboard anchors (DESIGN.md section 9, plan 15.6). Every `credential_*` key lives on the Credential page.
_STATUS = "credential#status"
_BUDGET = "credential#budget"
_COOLDOWNS = "upstream#cooldowns"
_POLICY = "policy#summary"

# The v2 liveness endpoint (plan 13.4): it answers with the logged-in account's user id, which lets the
# H-CRED-AUTH check confirm the cookie still belongs to the same account (C1), not just that it works.
DEFAULT_PROBE_URL = "https://users.roblox.com/v1/users/authenticated"

# The v1 constant TOKEN_PROBE_URL (app/proxy.py). Kept only as `v1_default` for the "v1 -> v2" display.
V1_PROBE_URL = "https://accountinformation.roblox.com/v1/birthdate"

SETTINGS: list[SettingSpec] = [
    SettingSpec(
        key="credential_enabled",
        group=Group.CREDENTIAL,
        label="Use the Roblox credential",
        type=SettingType.BOOL,
        default=1,
        description=(
            "Master switch for Roxy's single Roblox account cookie (the credential). When on, Roxy sends it "
            "for its own liveness checks and with caller requests to endpoints the endpoint policy marks 'sent "
            "with Roxy's account' (public reads such as catalog search and followers lists). Blocked endpoints "
            "never reach Roblox at all. When off, no request Roxy makes to Roblox carries the account."
        ),
        pages=(_STATUS,),
        if_enabled=(
            "Scheduled liveness checks run every credential_probe_interval_min minutes and the Credential page "
            "shows whether the account still works. Requests to endpoints sent with the account go out from the "
            "server's own IP with it, paced by the credential rate limit."
        ),
        if_disabled=(
            "The account is never sent. Liveness checks and the credential health checks stop, so an expired "
            "or rejected cookie is not noticed until this is turned back on. Requests the policy would send with "
            "the account go out without it, so endpoints that need a logged-in account fail for callers. The "
            "stored credential is kept; turning this off does not delete or replace it."
        ),
        risk=Risk.MEDIUM,
        apply=Apply.LIVE,
        related_settings=(
            "credential_probe_interval_min",
            "credential_bucket_per_min",
        ),
        notes=(
            "This is the quick, reversible way to stop all account use, for example while you investigate a "
            "leak guard alert. Replacing or deleting the credential itself is a separate, audited action on "
            "the Credential page, and Roxy never switches to another account on its own."
        ),
    ),
    SettingSpec(
        key="credential_bucket_per_min",
        group=Group.CREDENTIAL,
        label="Credential rate limit",
        type=SettingType.INT,
        default=20,
        unit="requests per minute",
        min=1,
        max=120,
        step=1,
        description=(
            "The steady pace at which Roxy may send requests that carry the Roblox account, shared by all "
            "workers. Requests are spaced evenly (at 20 per minute, one every 3 seconds) instead of being "
            "allowed in clumps, and every credential call counts: caller traffic, liveness checks, health "
            "checks and admin lookups."
        ),
        pages=(_BUDGET,),
        if_raised=(
            "More caller requests carry the account, but the account makes more calls per minute from one server IP, "
            "which raises the chance of Roblox 429 answers on the account and of Roblox treating it as "
            "automated. v1 allowed about 88 per minute, and that account traffic was the largest cause of its "
            "Roblox 429s."
        ),
        if_lowered=(
            "The account is quieter and safer. More caller requests go out anonymously instead; a request to an "
            "endpoint that only answers signed-in users waits longer for a turn, and when the wait runs out the "
            "caller gets a 429 with Retry-After instead of an answer. The value must stay above "
            "credential_probe_reserved_per_min so Roxy's own checks keep their reserved share."
        ),
        risk=Risk.MEDIUM,
        high_risk_if=(
            RiskCondition(
                RiskOp.GT,
                60,
                "More than one account call per second on average. v1 was tuned to stay under about 100 calls "
                "per minute, and many Roblox endpoints allow one account far less, so at this pace 429s on the "
                "account, or a Roblox review of it, become likely.",
            ),
        ),
        apply=Apply.LIVE,
        related_settings=(
            "credential_bucket_burst",
            "credential_probe_reserved_per_min",
            "global_bucket_per_min",
        ),
        related_recommendations=("UP-429-CREDENTIAL", "SEC-DEFAULTS"),
        renamed_from="token_budget_requests",
        v1_default=95,
        notes=(
            "Replaces v1's token_budget_requests (95) per token_budget_window (65 seconds): about 88 calls per "
            "minute with no pacing, so the whole budget could leave in about one second. The meaning changed "
            "from a count per window to an evenly paced rate, so the v1 value is never imported. Credential "
            "calls also pass the global, host and endpoint buckets on Upstream > Buckets."
        ),
    ),
    SettingSpec(
        key="credential_bucket_burst",
        group=Group.CREDENTIAL,
        label="Credential burst",
        type=SettingType.INT,
        default=3,
        unit="requests",
        min=1,
        max=20,
        step=1,
        description=(
            "How many credential requests may go out back to back before the even pacing of "
            "credential_bucket_per_min applies. It lets a short cluster of calls through without waiting while "
            "the average stays at the configured rate. The burst is shared with Roxy's own credential checks: "
            "caller traffic gets this burst minus 1 and the checks' reserved sub-bucket gets 1 (at 1, a "
            "check also takes the traffic's slot), so no more than this many account calls ever leave back to "
            "back."
        ),
        pages=(_BUDGET,),
        if_raised=(
            "Larger clusters of account calls leave at the same moment. Back-to-back calls from one account "
            "and one IP are the burst shape Roblox's rate limiters punish most, so 429s on the account become "
            "more likely."
        ),
        if_lowered=(
            "Account calls are spread out more smoothly. At 1, every credential call waits its full turn (3 "
            "seconds apart at the default rate), so callers may wait longer."
        ),
        risk=Risk.MEDIUM,
        high_risk_if=(
            RiskCondition(
                RiskOp.GT,
                10,
                "More than 10 account calls can leave in the same instant. Unpaced bursts on the account were a "
                "main cause of v1's Roblox 429s.",
            ),
        ),
        apply=Apply.LIVE,
        related_settings=("credential_bucket_per_min", "credential_probe_reserved_per_min"),
        related_recommendations=("SEC-DEFAULTS",),
        notes=(
            "v1 had no burst limit at all: its 95 call budget could be spent in about one second by its worker "
            "threads. The v1 budget window (token_budget_window, 65 seconds) is folded into "
            "credential_bucket_per_min, so it has no v2 key of its own."
        ),
    ),
    SettingSpec(
        key="credential_probe_interval_min",
        group=Group.CREDENTIAL,
        label="Credential check interval",
        type=SettingType.INT,
        default=30,
        unit="minutes",
        min=0,
        max=1440,
        step=1,
        description=(
            "How often Roxy checks, on a schedule, that the credential still works by calling "
            "credential_probe_url with it. Each check is one account call, taken from the reserved probe share "
            "of the credential rate limit. 0 turns the scheduled check off; an admin can still run it by hand."
        ),
        pages=(_STATUS,),
        if_raised=(
            "Fewer account calls (48 per day at 30 minutes, 24 at 60), but an expired or rejected cookie is "
            "noticed later, so endpoints sent with the account may fail for longer before you are alerted."
        ),
        if_lowered=(
            "Expiry is noticed sooner, at the cost of more account calls: every 5 minutes is 288 calls per day "
            "just to check. More than 6 internal credential calls in an hour triggers the CRED-PROBE-COST "
            "recommendation. At 0 no scheduled check runs and expiry shows only when someone checks by hand."
        ),
        risk=Risk.LOW,
        high_risk_if=(
            RiskCondition(
                RiskOp.IN,
                (1, 2, 3, 4),
                "Checking more often than every 5 minutes spends more than 288 account calls per day on checks "
                "alone: a steady, machine-like pattern on the account that buys very little earlier warning.",
            ),
        ),
        apply=Apply.LIVE,
        related_settings=(
            "credential_probe_url",
            "credential_probe_reserved_per_min",
            "credential_enabled",
            "health_auto_include_credential",
            "insight_cred_probe_cost_max_per_hour",
        ),
        related_recommendations=("CRED-PROBE-COST", "SEC-DEFAULTS"),
        notes=(
            "Scheduled health runs call Roblox with the account only when health_auto_include_credential is 1. "
            "With credential_enabled at 0 no check runs, whatever this value is. Expected account use at the "
            "defaults, counting only Roxy's own checks, is about 50 to 60 calls per day."
        ),
    ),
    SettingSpec(
        key="credential_probe_url",
        group=Group.CREDENTIAL,
        label="Credential check URL",
        type=SettingType.STRING,
        default=DEFAULT_PROBE_URL,
        max_length=300,
        description=(
            "The Roblox address Roxy calls with the credential to check that it still works. It must be an "
            "https GET endpoint on an allowed Roblox host that returns the logged-in account's user id, so the "
            "check (H-CRED-AUTH) can also confirm the cookie still belongs to the same account."
        ),
        pages=(_STATUS,),
        risk=Risk.MEDIUM,
        high_risk_if=(
            RiskCondition(
                RiskOp.NE,
                DEFAULT_PROBE_URL,
                "A different URL changes where the account cookie is sent on every check. If the new endpoint "
                "does not return the account's user id, Roxy can no longer confirm it is still the same account, "
                "and an endpoint with side effects could act on the account every time it is checked.",
            ),
        ),
        apply=Apply.LIVE,
        related_settings=(
            "credential_probe_interval_min",
            "credential_enabled",
            "allowed_roblox_hosts",
            "strict_host_allowlist",
        ),
        related_recommendations=("SEC-DEFAULTS",),
        v1_default=V1_PROBE_URL,
        notes=(
            "Was the fixed v1 constant TOKEN_PROBE_URL (accountinformation.roblox.com/v1/birthdate), which "
            "showed the cookie worked but not whose it was. The credential is only ever sent over https to "
            "allowed Roblox hosts, and redirects off roblox.com are never followed with it."
        ),
    ),
    SettingSpec(
        key="credential_probe_reserved_per_min",
        group=Group.CREDENTIAL,
        label="Reserved rate for credential checks",
        type=SettingType.INT,
        default=2,
        unit="requests per minute",
        min=1,
        max=10,
        step=1,
        description=(
            "The part of credential_bucket_per_min kept for Roxy's own credential checks (scheduled liveness "
            "checks and health checks), in a separate sub-bucket. A check never waits behind caller "
            "traffic, and caller traffic can never use up the checks' share; it gets the rest of the rate."
        ),
        pages=(_BUDGET,),
        if_raised=(
            "More checks can run in the same minute without waiting, but less of the credential rate is left "
            "for caller traffic (at 20 per minute with a reserve of 5, only 15 remain)."
        ),
        if_lowered=(
            "More of the credential rate goes to caller traffic. When several checks start together, for "
            "example a health run during a scheduled check, they wait behind each other, which only delays "
            "the result."
        ),
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("credential_bucket_per_min", "credential_probe_interval_min"),
        notes="Checked when saved: the reserve must be strictly smaller than credential_bucket_per_min.",
    ),
    SettingSpec(
        key="credential_cooldown_default_s",
        group=Group.CREDENTIAL,
        label="Credential rest after a 429",
        type=SettingType.DURATION,
        default=60,
        unit="seconds",
        min=5,
        max=3600,
        step=1,
        description=(
            "How long Roxy stops using the credential, on every worker, after Roblox answers a credential "
            "request with 429 (too many requests) and no Retry-After header. When Roblox does say how long to "
            "wait, Roxy waits that long instead. During the rest, caller requests go out anonymously, and "
            "endpoints that only answer signed-in users answer 503 with Retry-After."
        ),
        pages=(_BUDGET, _COOLDOWNS),
        if_raised=(
            "The account rests longer after a 429, which makes a repeat 429 less likely, but endpoints that "
            "only answer signed-in users are unavailable to callers for longer."
        ),
        if_lowered=(
            "The account is used again sooner after a 429. Coming back too early tends to earn another 429, "
            "and repeated 429s on one account are what can get it reviewed by Roblox."
        ),
        risk=Risk.MEDIUM,
        high_risk_if=(
            RiskCondition(
                RiskOp.LT,
                15,
                "Below 15 seconds Roxy returns to the account almost as soon as Roblox asked it to slow down, "
                "the pattern most likely to turn one 429 on the account into many.",
            ),
        ),
        apply=Apply.LIVE,
        related_settings=(
            "cooldown_default_s",
            "cooldown_min_s",
            "cooldown_max_s",
            "credential_bucket_per_min",
        ),
        related_recommendations=("SEC-DEFAULTS",),
        renamed_from="token_expiration_cooldown",
        v1_default=15,
        notes=(
            "Replaces v1's token_expiration_cooldown (15 seconds), which paused only one worker and then spent "
            "an extra account call to re-check the cookie. In v2 the rest is shared by every worker and a 429 "
            "is never mistaken for an expired cookie. The meaning changed, so the v1 value is never imported."
        ),
    ),
    # --- The endpoint policy (D1 revised 2026-10-16, docs/endpoint_policy/BRIEF.md) ---------------------------
    SettingSpec(
        key="endpoint_policy_enforce",
        group=Group.CREDENTIAL,
        label="Refuse blocked endpoints",
        type=SettingType.BOOL,
        default=1,
        description=(
            "Whether Roxy refuses caller requests to endpoints the endpoint policy blocks (sign-in, account, "
            "money and creator endpoints). Blocked endpoints never carry Roxy's account either way: this only "
            "decides whether they are refused, or forwarded without the account and recorded as 'would block'."
        ),
        pages=(_POLICY,),
        if_enabled=(
            "Callers asking for a blocked endpoint get the refusal set by endpoint_policy_block_status and "
            "endpoint_policy_block_message, and nothing reaches Roblox."
        ),
        if_disabled=(
            "Shadow mode: blocked endpoints are forwarded without the account (like any anonymous request) and "
            "each one is recorded as 'would block' on the Endpoint policy page, so you can see what the policy "
            "would refuse before you turn it on. Roblox answers most of them with 401."
        ),
        risk=Risk.MEDIUM,
        high_risk_if=(
            RiskCondition(
                RiskOp.EQ,
                0,
                "Strangers can then reach login, logout and account endpoints through Roxy's server address "
                "(without Roxy's account), which Roblox may hold against that address.",
            ),
        ),
        apply=Apply.LIVE,
        related_settings=("endpoint_policy_block_status", "endpoint_policy_block_message", "credential_enabled"),
        related_recommendations=("SEC-DEFAULTS",),
    ),
    SettingSpec(
        key="endpoint_policy_block_status",
        group=Group.CREDENTIAL,
        label="Status code for blocked endpoints",
        type=SettingType.ENUM,
        default="403",
        options=(
            OptionSpec(
                "403",
                "403 Forbidden",
                "The honest answer: Roxy understood the request and will not forward it. HTTP libraries and Roblox "
                "games do not retry a 403.",
            ),
            OptionSpec(
                "404",
                "404 Not Found",
                "Treats a blocked endpoint as if it did not exist through Roxy. Not retried either, but it hides "
                "that the endpoint was refused on purpose.",
            ),
            OptionSpec(
                "500",
                "500 Internal Server Error",
                "Looks like a Roxy failure. Many HTTP libraries and Roblox games retry a 500, so one blocked call "
                "can turn into a loop, and these refusals count as server errors on Health and Overview.",
            ),
        ),
        description="The HTTP status code a caller gets for an endpoint the endpoint policy blocks.",
        pages=(_POLICY,),
        risk=Risk.LOW,
        high_risk_if=(
            RiskCondition(
                RiskOp.EQ,
                "500",
                "Callers retry 500 answers, and they show up as server errors in Roxy's own health numbers.",
            ),
        ),
        apply=Apply.LIVE,
        related_settings=("endpoint_policy_enforce", "endpoint_policy_block_message"),
        related_recommendations=("SEC-DEFAULTS",),
    ),
    SettingSpec(
        key="endpoint_policy_block_message",
        group=Group.CREDENTIAL,
        label="Message for blocked endpoints",
        type=SettingType.STRING,
        default=(
            "Roxy does not forward this Roblox endpoint because it acts on a signed-in account or returns private "
            "account data. See the Roxy guide for the list of blocked endpoints."
        ),
        max_length=400,
        description="The body of the refusal a caller gets for an endpoint the endpoint policy blocks.",
        pages=(_POLICY,),
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("endpoint_policy_block_status",),
        notes="Callers see this text. Must not contain em or en dash characters (style rule C5).",
    ),
]
