DEBUG = False
DIRECT_API_COOLDOWN = 65  # In seconds, how long to wait between requests to the actual Roblox API.
ROPROXY_COOLDOWN = 65  # In seconds, how long to wait between roproxy requests.
TOKEN_EXPIRATION_COOLDOWN = (
    15 if not DEBUG else 5
)  # In seconds, how long to wait before retrying a token to see if it's actually expired.
EMAIL_COOLDOWN = 600  # In seconds, how long to wait between sending expiration emails.
TWO_FA_EXPIRATION = 30 if DEBUG else 30  # In seconds, how long a 2FA code is valid for.
CHALLENGE_EXPIRATION = 30 if DEBUG else 15  # In seconds, how long a challenge code is valid for.
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
