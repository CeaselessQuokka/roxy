import auth
import config
import hashlib
import hmac
import runtime
import time
import secrets
from threading import Timer as delay

KEY = auth.read_admin_credentials()[2].encode()

challenges = dict()  # hash: expiration_time


def is_challenge_valid(challenge: str) -> bool:
    expiration_time = challenges.pop(challenge, None)
    return expiration_time is not None and time.time() < expiration_time  # Expiration check for extra safety.


def generate_challenge(ip: str, user_agent: str) -> str:
    expiration = runtime.get_setting("challenge_expiration") or config.CHALLENGE_EXPIRATION
    originalMessage = f"{ip}|{user_agent}|{time.time()}".encode()
    newMessage = hmac.new(KEY, originalMessage, hashlib.sha256).hexdigest().encode()
    challenge = hmac.new(secrets.token_bytes(16), newMessage, hashlib.sha256).hexdigest()
    challenges[challenge] = time.time() + expiration
    delay(expiration, lambda: challenges.pop(challenge, None)).start()
    return challenge
