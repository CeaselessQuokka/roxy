import auth
import config
import hashlib
import hmac
import mail
import secrets
import time
from threading import Timer as delay

DIGITS = config.TWO_FA_DIGITS
EXPIRATION_TIME = config.TWO_FA_EXPIRATION
KEY = auth.read_admin_credentials()[2].encode()

codes = dict()  # hashed_code: expiration_time


def is_code_valid(code: str) -> bool:
    expiration_time = codes.pop(hash_code(code), None)
    return expiration_time is not None and time.time() < expiration_time  # Expiration check for extra safety.


def invalidate_2fa(hashed_code: str):
    codes.pop(hashed_code, None)


def hash_code(code: str) -> str:
    return hmac.new(KEY, code.encode(), hashlib.sha256).hexdigest()


def generate_2fa(expires_in: int = EXPIRATION_TIME) -> str:
    code = f"{secrets.randbelow(10**DIGITS):0{DIGITS}}"
    hashed_code = hash_code(code)
    codes[hashed_code] = time.time() + expires_in
    delay(expires_in, lambda: invalidate_2fa(hashed_code)).start()
    return code


def send_2fa(to: str, subject: str = "Admin 2FA") -> str:
    code = generate_2fa()
    mail.send(to, subject, code)
    return code
