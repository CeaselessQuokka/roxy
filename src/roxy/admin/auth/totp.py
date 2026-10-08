"""TOTP, the authenticator app second factor: code checking, the encrypted secret, and enrollment QR codes.

What this is
    `match_step(secret, code, now)` checks a 6-digit authenticator code (RFC 6238: 30 s steps, accepting the step
    before and after the current one) and returns WHICH step it matched. `TotpCipher` encrypts and decrypts the
    shared secret with AES-GCM under the `totp_encryption_key` credential. `new_secret`, `provisioning_uri`,
    `qr_svg_data_uri` and `qr_terminal` support enrollment in the browser and on the server console.

Why it exists
    Owner decision D5 makes TOTP mandatory. A TOTP code is HMAC(secret, current 30 s step) cut to 6 digits, so
    the server and the phone agree without talking to each other. Two rules make it safe (plan 9.5):
      * +/- 1 step only: phones and servers drift a little, but a wider window gives a stolen code a longer life.
      * each step once per user: a code seen over someone's shoulder must not work a second time. The flow keeps
        the last accepted step per user (`transactions.py`) and refuses any step that is not newer.
    The secret is stored encrypted (plan 9.8): a copied database file or backup alone does not reveal it. It does
    not protect against a compromise of the running host, which holds the key.

How it works
    - Codes are compared with `hmac.compare_digest` for every candidate step, and the loop always runs over all
      three steps, so the time taken does not reveal which step (if any) matched.
    - Ciphertext layout: one version byte, a 12-byte random nonce, then the AES-GCM output. The associated data
      binds a secret to its admin user id, so a secret copied onto another account row does not decrypt.
    - The key file accepts 64 hex characters, base64 of 32 bytes, or 32 raw bytes (`core/iphash.py`).

What to read next
    `roxy/admin/auth/flow.py` (`_verify_totp`, where the replay guard is applied), then
    `roxy/admin/auth/enrollment.py`.
"""

from __future__ import annotations

import base64
import hmac
import os
from pathlib import Path
from urllib.parse import quote

import pyotp
import segno
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from roxy.core.iphash import decode_key_material

TOTP_DIGITS = 6
TOTP_STEP_S = 30
TOTP_WINDOW_STEPS = 1
"""Accepted drift in steps on each side of the current one (plan 9.5)."""

TOTP_ISSUER = "Roxy"
TOTP_KEY_NAME = "totp_encryption_key"
"""File name of the systemd credential holding the AES key (plan 9.8)."""

_CIPHER_VERSION = b"\x01"
_NONCE_BYTES = 12
SECRET_BYTES = 20  # 160 bits, the RFC 4226 recommended HMAC-SHA1 key size


class TotpKeyMissing(RuntimeError):
    """The `totp_encryption_key` credential is missing or unusable, so TOTP secrets cannot be read or stored."""


def new_secret() -> str:
    """A fresh random shared secret in base32 (what authenticator apps expect), without padding."""
    return base64.b32encode(os.urandom(SECRET_BYTES)).decode("ascii").rstrip("=")


def current_step(now: float) -> int:
    """The 30 s step number at wall clock time `now`."""
    return int(now // TOTP_STEP_S)


def code_for_step(secret: str, step: int) -> str:
    """The 6-digit code of `secret` at `step` (used by tests and by `match_step`)."""
    return pyotp.TOTP(secret, digits=TOTP_DIGITS, interval=TOTP_STEP_S).generate_otp(step)


def code_at(secret: str, now: float) -> str:
    """The code an authenticator app shows at time `now`."""
    return code_for_step(secret, current_step(now))


def match_step(secret: str, code: str, now: float, *, window: int = TOTP_WINDOW_STEPS) -> int | None:
    """The newest step within +/- `window` of `now` whose code equals `code`, or None.

    The caller decides whether that step was already used (replay guard); this function only does the math.
    """
    candidate = code.strip().replace(" ", "")
    if len(candidate) != TOTP_DIGITS or not candidate.isascii() or not candidate.isdigit():
        return None
    base = current_step(now)
    try:
        totp = pyotp.TOTP(secret, digits=TOTP_DIGITS, interval=TOTP_STEP_S)
        codes = [(step, totp.generate_otp(step)) for step in range(base - window, base + window + 1)]
    except Exception:  # a corrupt secret must look like a wrong code, never like a server error
        return None
    matched: int | None = None
    for step, expected in codes:
        # No early exit: every candidate is compared, whatever matched first.
        if hmac.compare_digest(expected, candidate):
            matched = step
    return matched


def provisioning_uri(secret: str, username: str, issuer: str = TOTP_ISSUER) -> str:
    """The `otpauth://` URI an authenticator app scans (account label `issuer:username`)."""
    label = quote(f"{issuer}:{username}", safe=":@")
    return (
        f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer)}&algorithm=SHA1"
        f"&digits={TOTP_DIGITS}&period={TOTP_STEP_S}"
    )


def qr_svg_data_uri(uri: str) -> str:
    """The URI as a QR code SVG in a `data:` URL (allowed by the page CSP `img-src 'self' data:`)."""
    return str(segno.make(uri, error="m").svg_data_uri(scale=5, border=2, dark="#000", light="#fff"))


def qr_terminal(uri: str) -> str:
    """The URI as a QR code drawn with text blocks, for `scripts/create_admin.py` on the server console."""
    import io

    buffer = io.StringIO()
    segno.make(uri, error="m").terminal(out=buffer, compact=True, border=2)
    return buffer.getvalue()


class TotpCipher:
    """AES-GCM encryption of TOTP secrets under the `totp_encryption_key` credential (plan 9.8)."""

    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise TotpKeyMissing("totp_encryption_key must be 32 bytes (64 hex characters)")
        self._aead = AESGCM(key)

    @staticmethod
    def _aad(context: str) -> bytes:
        return f"roxy-totp:{context}".encode()

    def encrypt(self, secret: str, context: str) -> bytes:
        """Encrypt `secret`, bound to `context` (`user:<id>` for stored secrets)."""
        nonce = os.urandom(_NONCE_BYTES)
        return _CIPHER_VERSION + nonce + self._aead.encrypt(nonce, secret.encode("ascii"), self._aad(context))

    def decrypt(self, blob: bytes, context: str) -> str | None:
        """The secret, or None when the blob is damaged, from another key, or bound to another context."""
        if len(blob) <= 1 + _NONCE_BYTES or blob[:1] != _CIPHER_VERSION:
            return None
        nonce = blob[1 : 1 + _NONCE_BYTES]
        try:
            return self._aead.decrypt(nonce, blob[1 + _NONCE_BYTES :], self._aad(context)).decode("ascii")
        except (InvalidTag, UnicodeDecodeError, ValueError):
            return None


def user_context(user_id: int) -> str:
    """The AES-GCM associated data label for a stored secret."""
    return f"user:{user_id}"


def load_totp_key(credentials_dir: Path | None) -> bytes | None:
    """Read the `totp_encryption_key` credential, or None when it is missing or not 32 bytes."""
    if credentials_dir is None:
        return None
    try:
        raw = (credentials_dir / TOTP_KEY_NAME).read_bytes()
    except OSError:
        return None
    key = decode_key_material(raw)
    return key if len(key) == 32 else None


def load_cipher(credentials_dir: Path | None) -> TotpCipher | None:
    """A cipher for the configured key, or None when the credential is missing."""
    key = load_totp_key(credentials_dir)
    return TotpCipher(key) if key is not None else None
