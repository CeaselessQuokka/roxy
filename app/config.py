DEBUG = False
DIRECT_API_COOLDOWN = 65  # In seconds, how long to wait between requests to the actual Roblox API.
ROPROXY_COOLDOWN = 65  # In seconds, how long to wait between roproxy requests.
TOKEN_EXPIRATION_COOLDOWN = (
    30 if not DEBUG else 5
)  # In seconds, how long to wait before retrying a token to see if it's actually expired.
EMAIL_COOLDOWN = 600  # In seconds, how long to wait between sending expiration emails.
TWO_FA_EXPIRATION = 30 if DEBUG else 30  # In seconds, how long a 2FA code is valid for.
TWO_FA_DIGITS = 16  # How many digits a 2FA code has.
TOKEN_PREFIX = "_|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in-as-you-and-to-steal-your-ROBUX-and-items.|_"
MAX_LOGIN_RECORDS = 50  # How many login attempts to keep in memory.
MAX_EXPLOIT_RECORDS = 50  # How many exploit attempts to keep in memory
