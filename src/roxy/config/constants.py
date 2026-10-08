"""Constants: the few fixed values that are deliberately NOT runtime settings, each with the reason why.

What this is
    Every row of plan 15.4 "Kept as a constant", as a module-level name with its value and a comment giving the
    reason it is fixed in code instead of tunable in the settings catalog. Plus a short, clearly marked section of
    bounds that v2 added for tables v1 did not have (routing rules, bans, access lists), so nothing is unbounded.

Why it exists
    Plan principle P3 says every tunable lives in `config/catalog.py`. A value belongs here instead only when
    changing it at runtime would break something (histogram bounds that must stay mergeable), when it is a public
    fact (the Roblox cookie warning text), when it is a protocol rule (which error statuses may be cached), or when
    it is a safety ceiling that bounds memory or per-request work (plan P9: every map, table and file is bounded).
    Keeping them in one module with their reasons means a reviewer can audit every "magic number" in one read,
    and `tests/unit/config/test_constants.py` pins the 15.4 values.

How it works
    Plain names, no logic. Values that already have a single home elsewhere are re-exported from there instead of
    copied (the Roblox warning text from `core/redact.py`, the status sources from `core/reasons.py`), so there is
    exactly one copy of each. Closed vocabularies (rule modes, kinds, scopes, tarpit categories) are tuples here
    and `Literal` types in `rules/models.py`; a test checks the two agree.

What to read next
    `roxy/config/defaults.py` (the built-in data Roxy ships: default rules, tiers, ignored params and hosts),
    then `roxy/rules/models.py` (where the rule caps and text bounds below are enforced).
"""

from __future__ import annotations

from typing import Final

from roxy.core.reasons import Source
from roxy.core.redact import TOKEN_PREFIX

# --- Public facts and protocol rules ----------------------------------------------------------------------------------

# TOKEN_PREFIX is re-exported from core/redact.py (one copy, listed in __all__). Reason: a public Roblox string used
# by the auth smuggling check and the log redaction filter; a fact about Roblox, not something to tune.

# Reason: protocol semantics. Only these upstream errors describe the requested resource and may be cached (with
# `cache_error_ttl_seconds`); 429 and 5xx describe Roblox's state at that moment and must never be served as content.
CACHEABLE_ERROR_STATUSES: Final[frozenset[int]] = frozenset({400, 403, 404, 410})

# Reason: stored histograms are merged by adding bucket counts, which only works while every row uses the same
# bounds (plan 6.4). Changing them would make old and new rows incomparable. 20 finite upper bounds in
# milliseconds plus one overflow bucket = 21 buckets.
LATENCY_BUCKET_BOUNDS_MS: Final[tuple[int, ...]] = (
    5,
    10,
    20,
    35,
    50,
    75,
    100,
    150,
    200,
    300,
    500,
    750,
    1000,
    1500,
    2000,
    3000,
    5000,
    8000,
    12000,
    20000,
)
LATENCY_BUCKET_COUNT: Final[int] = len(LATENCY_BUCKET_BOUNDS_MS) + 1  # the last bucket is "over 20000 ms"

# Reason: host validation for the credential header (plan C2 item 7). There is no cookie jar any more; the value
# only says which hosts may ever receive the credential.
TOKEN_COOKIE_DOMAIN: Final[str] = ".roblox.com"  # noqa: S105 (a domain, not a password)

# --- Throttle ladder (plan 10.4) --------------------------------------------------------------------------------------

# Reason (v1): more rungs than this is a configuration no one can reason about.
MAX_THROTTLE_TIERS: Final[int] = 12
# Reason (v1): one rung's multiplier is capped so a typo cannot block a caller for weeks.
MAX_THROTTLE_MULTIPLIER: Final[int] = 1000
# Reason: bounds per-rung statistics; above MAX_THROTTLE_TIERS on purpose so a shrunk ladder keeps old stats.
MAX_TRACKED_STRIKE_TIERS: Final[int] = 32

# --- Rule caps (matched per request, so bounded) ----------------------------------------------------------------------

# Reason: unchanged from v1; every enabled rule is consulted per request, so the count is bounded.
MAX_ENDPOINT_RULES: Final[int] = 200
MAX_ENDPOINT_BLOCKS: Final[int] = 200
# Reason: 200 -> 500. v2 ships default rules and the TTL tuner proposes per-endpoint rules; matching uses a
# precompiled, specificity-sorted index (rules/match.py PatternIndex), so 500 rules cost microseconds.
MAX_CACHE_RULES: Final[int] = 500
# Reason: unchanged from v1; UA and header rules are evaluated in order on every request.
MAX_USER_AGENT_RULES: Final[int] = 100
MAX_HEADER_RULES: Final[int] = 100
# Reason: 100 -> 500. Bypass entries now expire by default (24 h) and are CIDR aware, so load-test and office
# ranges need more short-lived rows; lookups are a per-prefix-length dictionary match, not a scan.
MAX_THROTTLE_BYPASS_IPS: Final[int] = 500
# Reason: 50 -> 100. v2 ships 9 default params and CACHE-KEYSPLIT adds params with one click; cache keys are built
# from a set, so the size does not affect hot-path cost.
MAX_CACHE_IGNORED_PARAMS: Final[int] = 100
# Reason: unchanged from v1 (fingerprint value suppression list).
MAX_IGNORED_VALUE_HEADERS: Final[int] = 200

# --- Text and value bounds for rules ----------------------------------------------------------------------------------

# Reason (v1): bounds caller-facing admin text (refusal messages in blocks, rules, tiers, filters).
MAX_RULE_MESSAGE: Final[int] = 400
# Reason: bounds regex and substring matching cost per request.
MAX_USER_AGENT_NEEDLE: Final[int] = 200
# Reason: a cooldown longer than an hour is a ban; use a ban instead.
MAX_USER_AGENT_RULE_COOLDOWN: Final[float] = 3600.0

# --- Form defaults ----------------------------------------------------------------------------------------------------

# Reason: form defaults only. The editors prefill these values; they are never applied on their own, so they are
# not settings (an admin always confirms the value of each rule they create).
DEFAULT_USER_AGENT_RULE_LIMIT: Final[int] = 10
DEFAULT_USER_AGENT_RULE_PERIOD: Final[int] = 60
DEFAULT_USER_AGENT_RULE_COOLDOWN: Final[float] = 2.0
DEFAULT_ENDPOINT_RULE_PERIOD: Final[int] = 60
DEFAULT_CACHE_RULE_TTL: Final[int] = 300

# --- Cache browser and key diagnostics --------------------------------------------------------------------------------

# Reason: the largest server-side page in the cache browser; bounds one query.
CACHE_PAGE_MAX: Final[int] = 200
# Reason: the v1 suggestion list. v2 turns it into the default ignored set minus `v` (defaults.py,
# plan 15.5); `v` stays a suggestion only, because some Roblox APIs use `v` meaningfully.
SUGGESTED_CACHE_IGNORED_PARAMS: Final[tuple[str, ...]] = (
    "t",
    "_",
    "ts",
    "cb",
    "cachebust",
    "cache_bust",
    "rand",
    "random",
    "nocache",
    "v",
)
# Reason: key-spread diagnostic bounds; also the CACHE-KEYSPLIT rule defaults (plan 15.3 J2).
MAX_SPREAD_VALUES: Final[int] = 500
MIN_SPREAD_ENTRIES: Final[int] = 5

# --- Diagnostics record bounds (safety ceilings; plan P9) -------------------------------------------------------------

# Reason: characters of body shown inline in the live feed; the full body is in the capture.
MAX_LIVE_BODY_LENGTH: Final[int] = 2000
# Reason: characters of query or body kept per recent-request entry.
MAX_ENDPOINT_RECENT_BODY: Final[int] = 600
# Reason: 25 -> 50. Ceiling of the `endpoint_recent_requests` setting (its range in 15.3 I).
MAX_ENDPOINT_RECENT_REQUESTS: Final[int] = 50
# Reason: concrete paths kept per endpoint template.
MAX_CONCRETE_PER_TEMPLATE: Final[int] = 100
# Reason: client IPs kept per endpoint template drill-down.
MAX_IPS_PER_ENDPOINT_RECORD: Final[int] = 25
# Reason: client IPs kept per blocked or limited endpoint record.
MAX_IPS_PER_ATTEMPT_RECORD: Final[int] = 50
# Reason: endpoints kept per client record.
ACTIVITY_ENDPOINTS_PER_RECORD: Final[int] = 12
# Reason: refusal reasons are a closed enum in v2 (about 60), so this is only a safety ceiling.
MAX_REFUSAL_RECORDS: Final[int] = 100
# Reason: internal call sites are a closed list in code.
MAX_INTERNAL_REQUEST_RECORDS: Final[int] = 50
# Reason: failure signatures kept in the failures view.
MAX_REQUEST_FAILURE_RECORDS: Final[int] = 500
# Reason: distinct statuses kept; beyond that they are counted as `other`.
MAX_STATUS_CODES: Final[int] = 200
# Reason: retry reasons kept.
MAX_RETRY_REASONS: Final[int] = 100
# Reason: probe reasons kept in the summary.
MAX_EXPLOIT_SUMMARY: Final[int] = 100

# --- Shared-state row bounds ------------------------------------------------------------------------------------------

# Reason: 20000 -> 200000. Now rows in hot.db, not an in-memory dict, so the cap protects disk, not RAM; idle rows
# are pruned by `stale_ip_duration`.
MAX_TRACKED_THROTTLE_IPS: Final[int] = 200_000
# Reason: 10000 -> 100000. Same reason; rows in hot.db pruned after the lockout window.
MAX_TRACKED_LOGIN_IPS: Final[int] = 100_000
# Reason: 2000 -> 20000. Arrival-gap tracking moved to hot.db rows.
MAX_TARPIT_ARRIVALS: Final[int] = 20_000
# Reason: per-IP and per-reason tarpit breakdown rows.
MAX_TARPIT_IP_RECORDS: Final[int] = 200
MAX_TARPIT_REASON_RECORDS: Final[int] = 200
# Reason: ceiling on short-lived secrets per store (login transactions, email codes).
MAX_EXPIRABLES_PER_STORE: Final[int] = 500
# Reason: 45 -> 20. Heartbeats are every 5 s now, so 4 missed beats mean the worker is gone.
WORKER_STALE_AFTER: Final[int] = 20
# Reason: bounds `worker_heartbeat` rows.
MAX_TRACKED_WORKERS: Final[int] = 64

# --- Credential probes (plan C1, 13.3) --------------------------------------------------------------------------------

# Reason: one probe at a time fleet-wide (lease), so the account never sees parallel probes.
MAX_TOKEN_CHECK_WORKERS: Final[int] = 1
# Reason: seconds of grace on top of `request_timeout` for one probe.
TOKEN_CHECK_GRACE: Final[int] = 5
# Reason: there is exactly one credential (C1).
MAX_TOKEN_USAGE_RECORDS: Final[int] = 1

# --- Mail, alerts and cookies -----------------------------------------------------------------------------------------

# Reason: a hung SMTP server must never hang a task (notify/mail.py).
SMTP_TIMEOUT_S: Final[int] = 15
# Reason: journal lines included in a failure alert, after redaction (roxy-alert@).
ALERT_LOG_LINES: Final[int] = 60
# Reason: visitor discount marker only (the Overview visitor KPIs); not security relevant.
ADMIN_SEEN_COOKIE: Final[str] = "roxy_admin_seen"
ADMIN_SEEN_COOKIE_MAX_AGE_S: Final[int] = 180 * 86_400
# v1 MAX_CONTENT_LENGTH (Flask) is NOT a constant in v2: it is replaced by the `max_body_bytes` setting (plan 9.12).

# --- Fingerprint auto-ignore heuristics -------------------------------------------------------------------------------

# Reason: once a header was seen this many times and nearly every value was different, recording its values is
# provably pointless; the header is then added to `ignored_value_headers` automatically (v1 behavior).
AUTO_IGNORE_MIN_REQUESTS: Final[int] = 500
AUTO_IGNORE_UNIQUE_RATIO: Final[float] = 0.9

# --- Data kept in code ------------------------------------------------------------------------------------------------

# Reason: data, not a tunable. Path templating maps the segment before an id to a readable placeholder, so
# `.../users/29371917/outfits` becomes `.../users/{userId}/outfits` (v1 diagnostics `_ID_COLLECTION_NAMES`).
# Any other id-like segment becomes `{id}`. Changing an entry changes stored templates (TEMPLATE_VERSION).
PATH_TEMPLATE_PLACEHOLDERS: Final[dict[str, str]] = {
    "users": "userId",
    "user": "userId",
    "games": "gameId",
    "universes": "universeId",
    "universe": "universeId",
    "places": "placeId",
    "place": "placeId",
    "groups": "groupId",
    "group": "groupId",
    "assets": "assetId",
    "asset": "assetId",
    "badges": "badgeId",
    "badge": "badgeId",
    "bundles": "bundleId",
    "outfits": "outfitId",
    "items": "itemId",
    "passes": "passId",
    "gamepasses": "gamePassId",
    "servers": "serverId",
    "thumbnails": "thumbnailId",
}
PATH_TEMPLATE_FALLBACK_PLACEHOLDER: Final[str] = "id"

# Reason: data, not a tunable. Substrings (lowercase) that mark a User-Agent as an automated crawler or library for
# visitor classification (v1 config.CRAWLER_USER_AGENT_MARKERS, unchanged).
CRAWLER_USER_AGENT_MARKERS: Final[tuple[str, ...]] = (
    "bot",
    "crawl",
    "spider",
    "slurp",
    "curl",
    "wget",
    "python",
    "go-http",
    "java",
    "okhttp",
    "headless",
    "scrapy",
    "httpclient",
    "libwww",
    "feedfetcher",
    "facebookexternalhit",
    "ahrefs",
    "semrush",
    "bingpreview",
    "node-fetch",
    "axios",
    "postman",
    "insomnia",
)

# --- Closed enums (plan 15.4: "Closed enums in code") -----------------------------------------------------------------

# Who produced a status (v1 STATUS_SOURCES, now the `Source` enum in core/reasons.py; one copy).
STATUS_SOURCES: Final[tuple[str, ...]] = tuple(source.value for source in Source)

# How a User-Agent or header rule needle is matched (rules/match.py text_matches).
USER_AGENT_RULE_MODES: Final[tuple[str, ...]] = ("contains", "exact", "regex")
# Burst: N requests per period. Cooldown: a minimum gap between requests.
USER_AGENT_RULE_KINDS: Final[tuple[str, ...]] = ("burst", "cooldown")
# Budget per calling IP, or one budget shared by every IP sending that User-Agent.
USER_AGENT_RULE_SCOPES: Final[tuple[str, ...]] = ("ip", "global")
# Which part of a header a filter looks at: the name, the value, or either.
HEADER_RULE_SCOPES: Final[tuple[str, ...]] = ("key", "value", "either")
HEADER_RULE_MODES: Final[tuple[str, ...]] = ("contains", "exact", "regex")
# Refusal categories the tarpit may hold (one `tarpit_on_<category>` setting each). v1's eight plus `ban`, `spam`
# and `upstream_cooldown_retry` (plan 10.6); `user_agent_rule` finally has a working switch.
TARPIT_CATEGORIES: Final[tuple[str, ...]] = (
    "header_rule",
    "probe",
    "throttle",
    "throttle_all",
    "endpoint_rule",
    "blocked_endpoint",
    "auth_attempt",
    "user_agent_rule",
    "ban",
    "spam",
    "upstream_cooldown_retry",
)
ENDPOINT_RULE_SCOPES: Final[tuple[str, ...]] = ("ip", "place", "global")
ROUTING_RULE_MODES: Final[tuple[str, ...]] = ("prefer_direct", "prefer_rotator", "direct_only", "rotator_only")
ACCESS_LIST_KINDS: Final[tuple[str, ...]] = ("bypass", "allow_admin", "deny")
BAN_SUBJECT_TYPES: Final[tuple[str, ...]] = ("ip", "cidr", "place", "ua_hash")
THROTTLE_TIER_ACTIONS: Final[tuple[str, ...]] = ("throttle", "ban")
CACHE_RULE_METHODS: Final[tuple[str, ...]] = ("GET", "HEAD", "POST")
CREDENTIAL_ALLOWLIST_METHODS: Final[tuple[str, ...]] = ("GET", "HEAD")  # never a write method (D1, 9.13)

# --- Added in v2 (not rows of plan 15.4; tables v1 did not have, or v1 bounds that lived in code) ---------------------
# Each is a safety ceiling under plan P9 ("every map, queue, table and file is bounded").

# Reason (v1 runtime.py): notes are private admin text; v1 cut them at 200 characters.
MAX_RULE_NOTE: Final[int] = 200
# Reason: per-endpoint routing rules are matched on every upstream attempt, like endpoint rules.
MAX_ROUTING_RULES: Final[int] = 200
# Reason: rows are per host (about 40) and per endpoint template (top 2,000, plan 6.2), plus room for admins.
MAX_UPSTREAM_LIMITS: Final[int] = 2500
# Reason: the credential is used by as few endpoints as possible (D1: none by default); 50 entries is far more than
# any real need. The `credential_allowlist` table is the only allowlist (no setting, spec review 3).
MAX_CREDENTIAL_ALLOWLIST_RULES: Final[int] = 50
# Reason: matched on every request, and v1 had two entries. The `ignored_paths` table is the only list (no
# setting, spec review 4).
MAX_IGNORED_PATHS: Final[int] = 100
# Reason: the admin allowlist names a handful of networks the owner logs in from.
MAX_ADMIN_ALLOW_ENTRIES: Final[int] = 100
# Reason: deny entries are loaded into every worker's memory; 1,000 networks is far beyond manual use.
MAX_DENY_ENTRIES: Final[int] = 1000
# Reason: unexpired bans are loaded into every worker's memory (detectors create IP bans automatically), so the
# active set is bounded; expired bans are pruned by retention (`retention_expired_bans_days`).
MAX_ACTIVE_BANS: Final[int] = 10_000
# Reason: the longest ban a ladder rung may impose (7 days, the spam detectors' escalation ceiling); longer is a
# permanent ban, which is a deliberate admin action.
MAX_TIER_BAN_MINUTES: Final[int] = 10_080
# Reason: a bypass, deny or admin allow entry wider than /8 (IPv4) or /16 (IPv6) is almost certainly a typo that
# would exempt or block a large part of the internet.
MIN_ACCESS_PREFIX_V4: Final[int] = 8
MIN_ACCESS_PREFIX_V6: Final[int] = 16
# Reason (v1 bounds, kept): a per-endpoint or per-UA limit and its window.
MAX_RULE_LIMIT: Final[int] = 100_000
MAX_RULE_PERIOD_S: Final[int] = 86_400
# Reason (v1 bound, kept): a cache rule TTL longer than a day is better served by a purge-aware design.
MAX_CACHE_RULE_TTL_S: Final[int] = 86_400
# Reason: stale serving longer than a week shows callers data that is too old to be useful.
MAX_CACHE_RULE_STALE_TTL_S: Final[int] = 7 * 86_400
# Reason: normalization flags per cache rule (each is applied when the cache key is built).
MAX_CACHE_RULE_FLAGS: Final[int] = 16
# Reason: one audit before/after document; larger values are stored as a truncated preview.
MAX_AUDIT_JSON_BYTES: Final[int] = 64 * 1024
# Reason: admin reasons are short explanations, not documents.
MAX_REASON_LENGTH: Final[int] = 1000

__all__ = [
    "ACCESS_LIST_KINDS",
    "ACTIVITY_ENDPOINTS_PER_RECORD",
    "ADMIN_SEEN_COOKIE",
    "ADMIN_SEEN_COOKIE_MAX_AGE_S",
    "ALERT_LOG_LINES",
    "AUTO_IGNORE_MIN_REQUESTS",
    "AUTO_IGNORE_UNIQUE_RATIO",
    "BAN_SUBJECT_TYPES",
    "CACHEABLE_ERROR_STATUSES",
    "CACHE_PAGE_MAX",
    "CACHE_RULE_METHODS",
    "CRAWLER_USER_AGENT_MARKERS",
    "CREDENTIAL_ALLOWLIST_METHODS",
    "DEFAULT_CACHE_RULE_TTL",
    "DEFAULT_ENDPOINT_RULE_PERIOD",
    "DEFAULT_USER_AGENT_RULE_COOLDOWN",
    "DEFAULT_USER_AGENT_RULE_LIMIT",
    "DEFAULT_USER_AGENT_RULE_PERIOD",
    "ENDPOINT_RULE_SCOPES",
    "HEADER_RULE_MODES",
    "HEADER_RULE_SCOPES",
    "LATENCY_BUCKET_BOUNDS_MS",
    "LATENCY_BUCKET_COUNT",
    "MAX_ACTIVE_BANS",
    "MAX_ADMIN_ALLOW_ENTRIES",
    "MAX_AUDIT_JSON_BYTES",
    "MAX_CACHE_IGNORED_PARAMS",
    "MAX_CACHE_RULES",
    "MAX_CACHE_RULE_FLAGS",
    "MAX_CACHE_RULE_STALE_TTL_S",
    "MAX_CACHE_RULE_TTL_S",
    "MAX_CONCRETE_PER_TEMPLATE",
    "MAX_CREDENTIAL_ALLOWLIST_RULES",
    "MAX_DENY_ENTRIES",
    "MAX_ENDPOINT_BLOCKS",
    "MAX_ENDPOINT_RECENT_BODY",
    "MAX_ENDPOINT_RECENT_REQUESTS",
    "MAX_ENDPOINT_RULES",
    "MAX_EXPIRABLES_PER_STORE",
    "MAX_EXPLOIT_SUMMARY",
    "MAX_HEADER_RULES",
    "MAX_IGNORED_PATHS",
    "MAX_IGNORED_VALUE_HEADERS",
    "MAX_INTERNAL_REQUEST_RECORDS",
    "MAX_IPS_PER_ATTEMPT_RECORD",
    "MAX_IPS_PER_ENDPOINT_RECORD",
    "MAX_LIVE_BODY_LENGTH",
    "MAX_REASON_LENGTH",
    "MAX_REFUSAL_RECORDS",
    "MAX_REQUEST_FAILURE_RECORDS",
    "MAX_RETRY_REASONS",
    "MAX_ROUTING_RULES",
    "MAX_RULE_LIMIT",
    "MAX_RULE_MESSAGE",
    "MAX_RULE_NOTE",
    "MAX_RULE_PERIOD_S",
    "MAX_SPREAD_VALUES",
    "MAX_STATUS_CODES",
    "MAX_TARPIT_ARRIVALS",
    "MAX_TARPIT_IP_RECORDS",
    "MAX_TARPIT_REASON_RECORDS",
    "MAX_THROTTLE_BYPASS_IPS",
    "MAX_THROTTLE_MULTIPLIER",
    "MAX_THROTTLE_TIERS",
    "MAX_TIER_BAN_MINUTES",
    "MAX_TOKEN_CHECK_WORKERS",
    "MAX_TOKEN_USAGE_RECORDS",
    "MAX_TRACKED_LOGIN_IPS",
    "MAX_TRACKED_STRIKE_TIERS",
    "MAX_TRACKED_THROTTLE_IPS",
    "MAX_TRACKED_WORKERS",
    "MAX_UPSTREAM_LIMITS",
    "MAX_USER_AGENT_NEEDLE",
    "MAX_USER_AGENT_RULES",
    "MAX_USER_AGENT_RULE_COOLDOWN",
    "MIN_ACCESS_PREFIX_V4",
    "MIN_ACCESS_PREFIX_V6",
    "MIN_SPREAD_ENTRIES",
    "PATH_TEMPLATE_FALLBACK_PLACEHOLDER",
    "PATH_TEMPLATE_PLACEHOLDERS",
    "ROUTING_RULE_MODES",
    "SMTP_TIMEOUT_S",
    "STATUS_SOURCES",
    "SUGGESTED_CACHE_IGNORED_PARAMS",
    "TARPIT_CATEGORIES",
    "THROTTLE_TIER_ACTIONS",
    "TOKEN_CHECK_GRACE",
    "TOKEN_COOKIE_DOMAIN",
    "TOKEN_PREFIX",
    "USER_AGENT_RULE_KINDS",
    "USER_AGENT_RULE_MODES",
    "USER_AGENT_RULE_SCOPES",
    "WORKER_STALE_AFTER",
]
