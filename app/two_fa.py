import auth
import config
import hashlib
import hmac
import mail
import runtime
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


def hash_code(code: str) -> str:
    return hmac.new(KEY, code.encode(), hashlib.sha256).hexdigest()


def generate_2fa(expires_in: int = None) -> str:
    if expires_in is None:
        expires_in = runtime.get_setting("two_fa_expiration") or EXPIRATION_TIME
    code = f"{secrets.randbelow(10**DIGITS):0{DIGITS}}"
    hashed_code = hash_code(code)
    codes[hashed_code] = time.time() + expires_in
    delay(expires_in, lambda: codes.pop(hashed_code, None)).start()
    return code


def send_2fa(to: str, subject: str = "Admin 2FA") -> str:
    code = generate_2fa()
    mail.send(to, subject, code)
    return code
