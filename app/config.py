DEBUG = False
DIRECT_API_COOLDOWN = 65  # In seconds, how long to wait between requests to the actual Roblox API.
ROPROXY_COOLDOWN = 65  # In seconds, how long to wait between roproxy requests.
TOKEN_EXPIRATION_COOLDOWN = (
    15 if not DEBUG else 5
)  # In seconds, how long to wait before retrying a token to see if it's actually expired.
EMAIL_COOLDOWN = 600  # In seconds, how long to wait between sending expiration emails.
ERROR_EMAIL_COOLDOWN = 300  # In seconds, how long to wait between sending error-notification emails.
TWO_FA_EXPIRATION = 60 if DEBUG else 60  # In seconds, how long a 2FA code is valid for.
CHALLENGE_EXPIRATION = 60 if DEBUG else 60  # In seconds, how long a challenge code is valid for.
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

# --- Persistence ---
DATA_FILE = "/etc/roxy/roxy_data.json"  # Where minified-JSON stats/runtime state is saved.
AUTOSAVE_INTERVAL = 30 if not DEBUG else 5  # In seconds, how often to flush stats/state to disk.

# --- Proxying robustness ---
REQUEST_TIMEOUT = 15  # In seconds, how long to wait on an upstream Roblox request before failing.

# --- Extra diagnostics limits ---
MAX_ENDPOINT_RECORDS = 200  # How many distinct endpoints to track (most-frequent are kept).
MAX_EXPLOIT_SUMMARY = 100  # How many distinct exploit/probe reasons to keep aggregated.
MAX_LIVE_REQUESTS = 50  # How many recent requests to keep for the live feed.
MAX_LIVE_BODY_LENGTH = 2000  # Max characters of a request body to retain for the live feed.

# --- Admin session invalidation ---
INVALIDATION_TOKEN_EXPIRATION = 86400  # In seconds, how long an emailed "invalidate session" link stays valid.

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
