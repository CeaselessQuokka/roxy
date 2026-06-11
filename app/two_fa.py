import auth
import config
import hashlib
import hmac
import mail
import runtime
import secrets
import time

DIGITS = config.TWO_FA_DIGITS
EXPIRATION_TIME = config.TWO_FA_EXPIRATION
KEY = auth.read_admin_credentials()[2].encode()

# Codes are stored hashed in the shared runtime store (not in this process), so
# a login that starts on one gunicorn worker can be completed on another and
# expiry doesn't depend on an in-process timer surviving.


def is_code_valid(code: str) -> bool:
    if not isinstance(code, str) or not code:
        return False
    return runtime.consume_two_fa_code(hash_code(code))


def hash_code(code: str) -> str:
    return hmac.new(KEY, code.encode(), hashlib.sha256).hexdigest()


def generate_2fa(expires_in: int = None) -> str:
    if expires_in is None:
        expires_in = runtime.get_setting("two_fa_expiration", EXPIRATION_TIME)
    code = f"{secrets.randbelow(10**DIGITS):0{DIGITS}}"
    runtime.store_two_fa_code(hash_code(code), time.time() + expires_in)
    return code


def send_2fa(to: str, subject: str = "Admin 2FA") -> str:
    """Generate and email a 2FA code. Raises if the email cannot be sent."""
    code = generate_2fa()
    mail.send(to, subject, code)
    return code
