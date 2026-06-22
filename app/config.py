import os

DEBUG = False
DIRECT_API_COOLDOWN = 65  # In seconds, how long to wait between requests to the actual Roblox API.
ROPROXY_COOLDOWN = 65  # In seconds, how long to wait between roproxy requests.
TOKEN_EXPIRATION_COOLDOWN = (
    15 if not DEBUG else 5
)  # In seconds, how long to wait before retrying a token to see if it's actually expired.
EMAIL_COOLDOWN = 600  # In seconds, how long to wait between sending expiration emails.
ERROR_EMAIL_COOLDOWN = 300  # In seconds, how long to wait between sending error-notification emails.
TWO_FA_EXPIRATION = 60  # In seconds, how long a 2FA code is valid for.
CHALLENGE_EXPIRATION = 60  # In seconds, how long a challenge code is valid for.
TWO_FA_DIGITS = 16  # How many digits a 2FA code has.
TOKEN_PREFIX = "_|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in-as-you-and-to-steal-your-ROBUX-and-items.|_"
MAX_LOGIN_RECORDS = 20  # How many login attempts to keep in memory.
MAX_EXPLOIT_RECORDS = 20  # How many exploit attempts to keep in memory
MAX_CRAWL_RECORDS = 20  # How many crawl records to keep in memory
MAX_THROTTLE_RECORDS = 20  # How many throttle records to keep in
ALLOWED_REQUESTS_PER_MINUTE = 10  # How many requests an IP can make per THROTTLE_RESET_DURATION before being throttled.
THROTTLE_RESET_DURATION = 50 if not DEBUG else 15  # In seconds, how long it takes to reset ALLOWED_REQUESTS_PER_MINUTE.
STALE_IP_DURATION = (
    60 if not DEBUG else 15
)  # In seconds, how long to keep an IP in memory without requests before removing it.
MAX_RETRIES_PER_REQUEST = 3  # How many times to retry a request that has been given a 429 (sometimes this isn't token related, it's related to the API endpoint itself)

# --- Admin session presence ---
# The session stays alive for as long as the admin is on the dashboard (the page
# heartbeats while visible). Once they leave, the session dies after this many
# seconds unless they come back.
ADMIN_SESSION_IDLE_TIMEOUT = 120
ADMIN_HEARTBEAT_INTERVAL = 10  # In seconds, how often the dashboard pings to keep the session alive.

# --- Login brute-force protection ---
MAX_LOGIN_FAILURES = 5  # Failed credential/2FA attempts per IP per window before a temporary lockout.
LOGIN_FAILURE_WINDOW = 600  # In seconds, the sliding lockout window.

# --- Trusted devices ---
TRUSTED_DEVICE_DURATION = 30 * 24 * 3600  # 30 days a trusted device may skip the 2FA step.

# --- Traffic history ---
TRAFFIC_HISTORY_MINUTES = 180  # How many per-minute traffic buckets to keep (dashboard shows the last hour).

# --- Persistence ---
# Env overrides let tests/dev boot the app without touching /etc/roxy.
DATA_FILE = os.environ.get("ROXY_DATA_FILE", "/etc/roxy/roxy_data.json")  # Minified-JSON stats/runtime state.
AUTOSAVE_INTERVAL = 30 if not DEBUG else 5  # In seconds, how often to flush stats/state to disk.

# Small, high-frequency shared file holding the request-routing state (global
# token-use window + RoProxy/Rotate cooldowns) so all gunicorn workers coordinate
# without thrashing the big data file. Separate from DATA_FILE on purpose.
ROUTING_FILE = os.environ.get("ROXY_ROUTING_FILE", "/etc/roxy/roxy_routing.json")

# Shared per-IP throttle state (per-IP request counts, per-endpoint + global
# rate-limit buckets, and login-failure windows), so all gunicorn workers enforce
# ONE shared limit instead of N workers each allowing the full quota. Also small,
# high-frequency, and flock-guarded — kept separate from DATA_FILE/ROUTING_FILE.
THROTTLE_FILE = os.environ.get("ROXY_THROTTLE_FILE", "/etc/roxy/roxy_throttle.json")
# Tiny shared file for cross-worker singletons that aren't per-request (e.g. email
# send de-duplication, so 4 workers don't each send the same alert).
COORD_FILE = os.environ.get("ROXY_COORD_FILE", "/etc/roxy/roxy_coord.json")
# Hard cap on distinct IPs tracked in the throttle file so a spoofed-IP flood
# can't bloat it; the oldest (least-recently-seen) entry is evicted past this.
MAX_TRACKED_THROTTLE_IPS = 20000

# --- Upstream method routing (RoProxy / Token / Rotate) ---
# A request picks one method by weighted random among those currently available.
# Base weights (percent-ish; they're normalized): RoProxy 10, Token 70, Rotate 20.
ROPROXY_WEIGHT = 10
TOKEN_WEIGHT = 70
ROTATE_WEIGHT = 20
# Once the token's usage in its window passes this "danger zone", its weight is
# progressively shifted to Rotate (then RoProxy) until the hard cap cuts it off.
TOKEN_DANGER_ZONE = 60

# --- IP rotation (DataImpulse or any HTTP proxy) ---
# The full proxy URL (e.g. http://user:pass@gw.dataimpulse.com:823, or just
# http://gw.dataimpulse.com:823 with IP-whitelist auth) is read from this file
# if present; the env var wins if set. Empty/missing => rotation disabled.
ROTATE_PROXY_FILE = os.environ.get("ROXY_ROTATE_PROXY_FILE", "/etc/roxy/rotate_proxy.txt")
ROTATE_PROXY_ENV = os.environ.get("ROXY_ROTATE_PROXY", "")
ROTATE_COOLDOWN = 60  # In seconds to pause Rotate after a streak of proxy-level failures.
ROTATE_MAX_FAILURES = 3  # Consecutive proxy failures before Rotate goes on cooldown.
# Verifying rotation: an IP-echo endpoint we fetch THROUGH the rotation proxy to
# learn (and log) which exit IP we got. DataImpulse responses to Roblox never
# reveal the exit IP, so this is the only way to confirm rotation is working.
ROTATE_IP_ECHO_URL = "https://api.ipify.org?format=json"
ROTATE_PROBE_TIMEOUT = 10  # Seconds for the exit-IP probe (kept short).
MAX_ROTATE_IPS = 20  # How many recent exit IPs to keep for verification.

# --- Proxying robustness ---
REQUEST_TIMEOUT = 15  # In seconds, how long to wait on an upstream Roblox request before failing.

# --- Internal token safety budget ---
# Roblox flags bursty bot behavior. The internal token must NEVER exceed this
# many requests per window; over-budget requests get a friendly try-later error
# instead of touching Roblox. (95/65s leaves leeway under a 100/60s detection
# threshold.) Tunable live from the dashboard Settings section.
TOKEN_BUDGET_REQUESTS = 95
TOKEN_BUDGET_WINDOW = 65  # In seconds.

# --- Global throttle-all defaults ---
# When the admin enables "throttle all", each IP is limited to this many requests
# per window. Strict by default (a softer alternative to a full pause), tunable live.
GLOBAL_THROTTLE_LIMIT = 1
GLOBAL_THROTTLE_PERIOD = 60  # In seconds.

# --- Extra diagnostics limits ---
MAX_ENDPOINT_RECORDS = 200  # How many distinct endpoints to track (most-frequent are kept).
MAX_EXPLOIT_SUMMARY = 100  # How many distinct exploit/probe reasons to keep aggregated.
MAX_LIVE_REQUESTS = 50  # How many recent requests to keep for the live feed.
MAX_LIVE_BODY_LENGTH = 2000  # Max characters of a request body to retain for the live feed.

# --- Admin session invalidation ---
INVALIDATION_TOKEN_EXPIRATION = 86400  # In seconds, how long an emailed "invalidate session" link stays valid.

# --- Endpoint controls ---
MAX_ENDPOINT_BLOCKS = 200  # How many distinct blocked-endpoint patterns to keep.
MAX_ENDPOINT_RULES = 200  # How many distinct per-endpoint rate rules to keep.
DEFAULT_ENDPOINT_RULE_PERIOD = 60  # In seconds, default window for a per-endpoint per-IP rate rule.
MAX_HEADER_RULES = 100  # How many distinct header-block rules to keep.
MAX_THROTTLE_BYPASS_IPS = 100  # How many IPs may be on the throttle-bypass allowlist.

# --- Error log + request fingerprints (kept until the admin clears them) ---
# Generous caps that act only as an out-of-memory guard against an attacker
# deliberately generating unbounded variety; real traffic stays well under.
MAX_ERROR_RECORDS = 2000  # Distinct error signatures retained.
MAX_HEADER_NAME_RECORDS = 1000  # Distinct header names retained.
MAX_USER_AGENT_RECORDS = 5000  # Distinct user-agents retained.
MAX_HEADER_VALUE_RECORDS = 300  # Distinct values retained per header name (drill-down).

# Substrings that mark a User-Agent as an automated crawler/bot (for visitor classification).
CRAWLER_USER_AGENT_MARKERS = [
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
]
