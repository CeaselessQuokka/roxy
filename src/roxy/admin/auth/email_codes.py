"""Emailed login codes: the D5 first-login bootstrap factor and the optional (off by default) email fallback.

What this is
    `new_code(digits)`, `digest(code, salt)` and `matches(...)` for the 16-digit code v1 used as its only second
    factor, the resend limits, and `send_code`, which mails it with v1's exact subject `Admin 2FA` and a body that
    is the code only.

Why it exists
    Owner decision D5: the authenticator app is mandatory, and an emailed code is accepted in two cases only:
    the one-time first login after the upgrade from v1 (`admin_users.mfa_bootstrap_pending`, set by the migrator),
    and when the admin turns on `admin_email_code_enabled`. v1's codes were global (any valid code satisfied any
    login, bug B9) and a resend left the old code valid. Here a code belongs to one login transaction, is stored
    only as a salted SHA-256 digest inside it, and a resend replaces it (plan 4.6 row 96).

How it works
    - The salt is the login transaction's own id hash, so equal codes in two transactions have unrelated digests.
      A digest (not argon2) is enough: a code has 53 bits of entropy and lives at most `two_fa_expiration` seconds.
    - Resends are limited per transaction: at least `RESEND_MIN_INTERVAL_S` apart and at most `MAX_SENDS_PER_TX`.
    - Sending goes through the notifier's direct mail path (`Notifier.send_message`): it is not an alert, so no
      severity filter, dedupe or hourly cap applies, and a failure is reported to the caller (503, v1 text).

What to read next
    `roxy/admin/auth/flow.py` (where codes are issued and checked), then `roxy/notify/notifier.py`.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import Any

EMAIL_SUBJECT = "Admin 2FA"
"""v1 subject, kept exactly (owners filter mail on it; plan 17.7)."""

RESEND_MIN_INTERVAL_S = 30
"""Minimum seconds between two codes for one login transaction."""

MAX_SENDS_PER_TX = 5
"""Codes one login transaction may send in total (the first one included)."""

SEND_FAILED_TEXT = "Could not send the 2FA email; please try again shortly."
"""v1 503 body, kept exactly."""


def new_code(digits: int) -> str:
    """A uniformly random code of exactly `digits` digits (leading zeros kept), like v1's."""
    digits = max(6, min(int(digits), 20))
    return f"{secrets.randbelow(10**digits):0{digits}d}"


def digest(code: str, salt: str) -> str:
    """The stored form of a code: SHA-256 over the transaction salt and the code."""
    return hashlib.sha256(f"roxy-email-code:{salt}:{code}".encode()).hexdigest()


def matches(candidate: str, stored_digest: str, salt: str) -> bool:
    """Constant-time comparison of a typed code with the stored digest."""
    cleaned = candidate.strip().replace(" ", "") if isinstance(candidate, str) else ""
    if not cleaned or not cleaned.isascii() or not cleaned.isdigit() or len(cleaned) > 20:
        # Still compare something, so the time taken does not depend on what was typed.
        hmac.compare_digest(stored_digest, "0" * len(stored_digest))
        return False
    return hmac.compare_digest(digest(cleaned, salt), stored_digest)


async def send_code(notifier: Any, to: str | None, code: str) -> None:
    """Mail `code` (body is the code only, as in v1). Raises when the mail could not be sent."""
    await notifier.send_message(EMAIL_SUBJECT, code, to=to)
