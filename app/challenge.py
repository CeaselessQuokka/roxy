import auth
import config
import hashlib
import hmac
import runtime
import secrets
import time

KEY = auth.read_admin_credentials()[2].encode()

# Challenges live in the shared runtime store (not in this process), so a login
# that starts on one gunicorn worker can be completed on another and expiry
# doesn't depend on an in-process timer surviving.


def is_challenge_valid(challenge: str) -> bool:
    if not isinstance(challenge, str) or not challenge:
        return False
    return runtime.consume_challenge(challenge)


def generate_challenge(ip: str, user_agent: str) -> str:
    expiration = runtime.get_setting("challenge_expiration", config.CHALLENGE_EXPIRATION)
    originalMessage = f"{ip}|{user_agent}|{time.time()}".encode()
    newMessage = hmac.new(KEY, originalMessage, hashlib.sha256).hexdigest().encode()
    challenge = hmac.new(secrets.token_bytes(16), newMessage, hashlib.sha256).hexdigest()
    runtime.store_challenge(challenge, time.time() + expiration)
    return challenge
