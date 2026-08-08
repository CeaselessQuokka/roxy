import os

DEBUG = False

# --- Response headers --------------------------------------------------------
# nginx terminates TLS and already sends Strict-Transport-Security, so the app
# stays quiet by default rather than emitting a duplicate header. Set
# ROXY_SEND_HSTS=1 if the app is ever fronted by something that doesn't add it.
SEND_HSTS = os.environ.get("ROXY_SEND_HSTS", "0") == "1"

# --- Reverse-proxy trust -----------------------------------------------------
# How many proxy hops in front of the app are OURS and therefore trustworthy.
# The client IP is taken from the RIGHTMOST end of X-Forwarded-For, skipping
# this many hops -- never the leftmost entry, which the caller writes and can
# forge (see index.get_client_ip). 1 = nginx only. Put 2 if Cloudflare (or any
# other CDN) also sits in front and appends a hop.
TRUSTED_PROXY_HOPS = int(os.environ.get("ROXY_TRUSTED_PROXY_HOPS", "1"))
TOKEN_EXPIRATION_COOLDOWN = (
    15 if not DEBUG else 5
)  # In seconds, how long to wait before retrying a token to see if it's actually expired.
EMAIL_COOLDOWN = 600  # In seconds, how long to wait between sending expiration emails.
ERROR_EMAIL_COOLDOWN = 300  # In seconds, how long to wait between sending error-notification emails.
TWO_FA_EXPIRATION = 60  # In seconds, how long a 2FA code is valid for.
CHALLENGE_EXPIRATION = 60  # In seconds, how long a challenge code is valid for.
TWO_FA_DIGITS = 16  # How many digits a 2FA code has.
# The literal prefix Roblox itself bakes into every real .ROBLOSECURITY cookie
# value. Roxy doesn't accept authenticated requests, but this is used to DETECT
# (and reject + log) anyone trying to smuggle a real Roblox session cookie into a
# request via any header — see index._detect_auth_attempt.
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
#
# Two files, split by value and by size:
#   STATE_FILE - the control plane (settings, endpoint/header rules, trusted
#                devices, pause flag). Small, precious, read on the request
#                path. Losing it means losing configuration.
#   DATA_FILE  - accumulated diagnostics. Large, disposable, rewritten wholesale
#                on every flush. Losing it costs nothing but history.
# Keeping them apart means an admin action no longer rewrites megabytes of
# stats, a stats read no longer parses the config, and the stats file can be
# deleted at any time without touching configuration.
STATE_FILE = os.environ.get("ROXY_STATE_FILE", "/etc/roxy/roxy_state.json")  # Control plane.
DATA_FILE = os.environ.get("ROXY_DATA_FILE", "/etc/roxy/roxy_data.json")  # Minified-JSON stats.
AUTOSAVE_INTERVAL = 30 if not DEBUG else 5  # In seconds, how often to flush stats/state to disk.
# Last-resort guard: a stats file larger than this is quarantined on load rather
# than parsed, because parsing it is what runs the box out of memory. Every
# record store is capped so this should never trigger; if it does, something new
# is unbounded and the dashboard error log will say so.
MAX_DATA_FILE_BYTES = 24 * 1024 * 1024

# Small, high-frequency shared file holding the request-routing state (global
# token-use window + Rotate's failure cooldown) so all gunicorn workers coordinate
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
# Shared tarpit state: the concurrency leases that stop held requests from eating
# every worker thread, plus the per-IP arrival times used to measure how often a
# tarpitted caller comes back. Separate file, same flock discipline.
TARPIT_FILE = os.environ.get("ROXY_TARPIT_FILE", "/etc/roxy/roxy_tarpit.json")
# Shared worker registry: each gunicorn worker heartbeats its pid/uptime/memory
# here so the dashboard can show the fleet instead of whichever worker answered.
WORKERS_FILE = os.environ.get("ROXY_WORKERS_FILE", "/etc/roxy/roxy_workers.json")
# Shared request/response CAPTURE ring: the full bodies behind the live feed.
# Deliberately its own file and deliberately NOT part of DATA_FILE, because this
# is the one store that holds attacker-controlled payloads of arbitrary size.
# Keeping it separate means it is bounded by its own byte budget + TTL, can be
# dropped at any moment, and can never contribute to the stats file growing.
CAPTURE_FILE = os.environ.get("ROXY_CAPTURE_FILE", "/etc/roxy/roxy_capture.json")
# Hard cap on distinct IPs tracked in the throttle file so a spoofed-IP flood
# can't bloat it; the oldest (least-recently-seen) entry is evicted past this.
MAX_TRACKED_THROTTLE_IPS = 20000

# --- Upstream method routing (Token / Rotate) ---
# A request picks one method by weighted random among those currently available.
# Base weights (percent-ish; they're normalized): Token 75, Rotate 25.
TOKEN_WEIGHT = 75
ROTATE_WEIGHT = 25
# Once the token's usage in its window passes this "danger zone", its weight is
# progressively shifted to Rotate until the hard cap cuts it off.
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

# --- Tarpit (slow-drip refusals) ---------------------------------------------
# A caller we have already decided to refuse can be made to WAIT for its error
# instead of getting it instantly. A synchronous client (which is what exploit
# HTTP wrappers usually are) can then only make one request per hold, so the
# hold is itself a rate limiter — the refusal costs them time instead of costing
# us a hot retry loop.
#
# The danger is self-DoS: gunicorn runs `workers x threads` concurrent slots
# (4 x 4 = 16 today) and a held request occupies one for the whole hold, so the
# concurrency cap below is not optional. Past the cap, callers get the same
# instant refusal they got before the tarpit existed.
#
# The hold also has to fit inside the timeouts wrapped around it: gunicorn kills
# a worker whose request exceeds `timeout` (90s, see gunicorn.conf.py) and nginx
# gives up at proxy_read_timeout (100s, see Tooling/nginx-roxy.conf). The 55s
# ceiling on the setting keeps the longest possible hold comfortably under both.
TARPIT_MIN_SECONDS = 8  # Randomised per request so the delay can't be learned...
TARPIT_MAX_SECONDS = 20  # ...and short enough to leave the request budget alone.
TARPIT_MAX_CONCURRENT = 6  # Held requests allowed at once, FLEET-wide. Must stay well under workers*threads.
TARPIT_SLOT_GRACE = 15  # Seconds a lease may outlive its hold before it's reclaimed (worker killed mid-hold).
# Hard ceiling on the tunable above, expressed as a FRACTION of the fleet's real
# request slots (workers x threads). The setting's own max is 64, which on a
# 16-slot fleet would let the tarpit consume every thread and take the proxy
# down — a misconfiguration the admin has no way to see coming. This clamp is
# applied at admission time, so raising the setting past what the fleet can
# afford quietly does nothing instead of quietly self-DoSing.
TARPIT_MAX_CAPACITY_FRACTION = 0.5
TARPIT_FALLBACK_SLOTS = 16  # Assumed workers x threads when the real figure can't be read.
MAX_TARPIT_IP_RECORDS = 200  # Distinct tarpitted IPs kept for the per-IP breakdown.
MAX_TARPIT_REASON_RECORDS = 200  # Distinct "which rule caused this hold" records kept.
MAX_TARPIT_ARRIVALS = 2000  # Distinct IPs whose last arrival time is kept (for the gap measurement).
TARPIT_HISTORY_MINUTES = 1500  # Per-minute hold buckets retained (~25h), for the request-frequency trend.
# Which refusals may be held. Each is an independent on/off setting
# (tarpit_on_<name>); see runtime._settings for the defaults and why.
TARPIT_CATEGORIES = (
    "header_rule",  # Caught by a Request Filter — traffic you explicitly fingerprinted.
    "probe",  # Not a Roblox URL / malformed — never a legitimate caller.
    "throttle",  # Ordinary per-IP rate limit. Also catches real users; off by default.
    "throttle_all",  # The global throttle-all limit. Also catches real users; off by default.
    "endpoint_rule",  # A per-endpoint rate rule.
    "blocked_endpoint",  # A blocked endpoint.
    "auth_attempt",  # Tried to smuggle a ROBLOSECURITY cookie.
)

# --- Worker registry ---------------------------------------------------------
# Each worker writes a heartbeat so the dashboard can show the whole fleet. A
# single worker's uptime is misleading on its own: gunicorn recycles workers at
# max_requests, so the number visibly jumps around depending on which worker
# answered the poll.
WORKER_HEARTBEAT_INTERVAL = 10  # In seconds, how often a worker refreshes its registry entry.
WORKER_STALE_AFTER = 45  # In seconds without a heartbeat before a worker is considered gone.
MAX_TRACKED_WORKERS = 64  # Hard ceiling on registry entries.

# --- Global throttle-all defaults ---
# When the admin enables "throttle all", each IP is limited to this many requests
# per window. Strict by default (a softer alternative to a full pause), tunable live.
GLOBAL_THROTTLE_LIMIT = 1
GLOBAL_THROTTLE_PERIOD = 60  # In seconds.

# --- Extra diagnostics limits ---
MAX_ENDPOINT_RECORDS = 200  # How many distinct endpoints to track (most-frequent are kept).
MAX_EXPLOIT_SUMMARY = 100  # How many distinct exploit/probe reasons to keep aggregated.
# The live feed is the first place anyone looks during an incident, and 50
# entries is under twenty seconds of history on a proxy under load — by the time
# the dashboard is open the interesting requests have already scrolled off.
MAX_LIVE_REQUESTS = 150  # How many recent requests to keep for the live feed.
MAX_LIVE_BODY_LENGTH = 2000  # Max characters of a request body to retain for the live feed.

# --- Per-endpoint recent requests --------------------------------------------
# Each endpoint template keeps a short ring of the most recent requests that hit
# it (who, with what query/body, and what came back), so "what exactly is this
# endpoint being asked for?" is answerable without waiting for the live feed to
# catch the next one. Fetched on demand, never in the dashboard poll.
ENDPOINT_RECENT_REQUESTS = 5  # Default ring length per endpoint template.
MAX_ENDPOINT_RECENT_REQUESTS = 25  # Hard ceiling on the tunable above.
MAX_ENDPOINT_RECENT_BODY = 600  # Characters of query/body kept per recent-request entry.
MAX_IPS_PER_ENDPOINT_RECORD = 25  # Distinct client IPs retained per endpoint template.

# --- Who is calling ----------------------------------------------------------
# Two views of the same traffic, because an attacker controls one of them and
# not the other. IPs churn (Roblox game servers hold hundreds); the Roblox-Id
# header names the PLACE the request came from and is stable per experience,
# which is what actually identifies a caller worth blocking.
MAX_IP_ACTIVITY_RECORDS = 400  # Distinct client IPs tracked in the Top Talkers view.
MAX_CALLER_RECORDS = 200  # Distinct Roblox place IDs tracked in the Callers view.
ACTIVITY_ENDPOINTS_PER_RECORD = 12  # Distinct endpoints retained per IP/caller record.
ACTIVITY_HISTORY_MINUTES = 120  # Per-minute request buckets retained per IP/caller (for rates).
MAX_REFUSAL_RECORDS = 100  # Distinct refusal reasons retained (each is a code path, so this is generous).
MAX_INTERNAL_REQUEST_RECORDS = 50  # Distinct internal (Roxy-originated) upstream call sites tracked.

# --- Request/response capture ------------------------------------------------
# The live feed shows metadata for every request; the actual bodies live here.
# Three independent ceilings, because any one of them alone has a failure mode:
# a count cap says nothing about size, a byte cap lets one quiet hour pin stale
# data forever, and a TTL alone is unbounded under a flood.
# Sized to outlast the live feed rather than to a round number: a capture window
# shorter than the feed means most cards in it open to "that expired", which
# reads as broken. The byte budget is the ceiling that actually binds — at a
# typical 1-2 KB per pair this count is reached long before it, and at 16 KB
# bodies the bytes win first. That is the intended order.
CAPTURE_MAX_RECORDS = 250  # How many captured request/response pairs are retained.
CAPTURE_MAX_BYTES = 4 * 1024 * 1024  # Total budget for the capture file; oldest entries evicted past it.
CAPTURE_MAX_BODY = 16 * 1024  # Characters kept per body (request and response counted separately).
CAPTURE_TTL_SECONDS = 900  # How long a capture may live regardless of the caps above.

# --- Admin session invalidation ---
INVALIDATION_TOKEN_EXPIRATION = 86400  # In seconds, how long an emailed "invalidate session" link stays valid.

# --- Endpoint controls ---
MAX_ENDPOINT_BLOCKS = 200  # How many distinct blocked-endpoint patterns to keep.
MAX_ENDPOINT_RULES = 200  # How many distinct per-endpoint rate rules to keep.
DEFAULT_ENDPOINT_RULE_PERIOD = 60  # In seconds, default window for a per-endpoint per-IP rate rule.
MAX_HEADER_RULES = 100  # How many distinct header-block rules to keep.
MAX_THROTTLE_BYPASS_IPS = 100  # How many IPs may be on the throttle-bypass allowlist.

# --- Error log + request fingerprints (kept until the admin clears them) ---
# EVERY record store in diagnostics.py is capped, and the cap is re-applied
# after the cross-worker merge (see diagnostics._trim_merged) -- a per-worker
# cap alone is not enough, because merging N workers' capped sets produces an
# uncapped union. Nothing here may grow without a ceiling.
MAX_ERROR_RECORDS = 1000  # Distinct error signatures retained.
MAX_REQUEST_FAILURE_RECORDS = 500  # Distinct "method: reason" failure signatures retained.
MAX_HEADER_NAME_RECORDS = 300  # Distinct header names retained.
MAX_USER_AGENT_RECORDS = 1000  # Distinct user-agents retained.
MAX_HEADER_VALUE_RECORDS = 200  # Distinct values retained per header name (drill-down).
MAX_STATUS_CODES = 200  # Distinct upstream status codes retained.
MAX_TOKEN_USAGE_RECORDS = 100  # Distinct token fingerprints retained.
MAX_IPS_PER_ATTEMPT_RECORD = 50  # Distinct IPs retained per blocked/rate-limited endpoint record.
MAX_RETRY_REASONS = 100  # Distinct retry reasons retained.
MAX_BUDGET_MINUTES = 1500  # Per-minute token-budget peaks retained (~25h).

# --- High-cardinality header values -----------------------------------------
# Some headers carry a unique value on EVERY request (traceparent is in every
# Roblox request), so enumerating their distinct values is unbounded work with
# no diagnostic payoff. For these we keep the header's name and request count
# but skip the per-value breakdown. The admin can edit this list live; these are
# the defaults applied on a fresh install.
DEFAULT_IGNORED_VALUE_HEADERS = (
    "traceparent",
    "tracestate",
    "x-request-id",
    "request-id",
    "x-correlation-id",
    "x-amzn-trace-id",
    "x-b3-traceid",
    "x-b3-spanid",
    "x-b3-parentspanid",
)
MAX_IGNORED_VALUE_HEADERS = 200
# Auto-ignore: once a header has been seen this many times AND nearly every
# request carried a different value, recording those values is provably
# pointless -- add it to the ignore list automatically (visible + reversible on
# the dashboard). Disable with the auto_ignore_high_cardinality setting.
AUTO_IGNORE_MIN_REQUESTS = 500
AUTO_IGNORE_UNIQUE_RATIO = 0.9  # distinct values / requests seen

# --- Dashboard ---------------------------------------------------------------
# get_diagnostics() merges every worker's stats before answering, which is the
# single most expensive thing the app does. The dashboard polls often, so the
# merge is throttled to at most once per this many seconds; polls in between
# answer from already-merged memory.
DIAGNOSTICS_FLUSH_INTERVAL = 10

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
