"""Egress crypto: the `credential_encryption_key` and the AES-GCM sealing of UI-set secrets (plan 9.8).

What this is
    `load_encryption_key(credentials_dir)` reads the 32-byte key from the systemd credential
    `credential_encryption_key`; `seal` and `unseal` encrypt and decrypt one value with AES-GCM; `derive_key`
    makes purpose-specific sub-keys (for example the key that fingerprints the credential).

Why it exists
    The service runs unprivileged, so when the admin replaces the Roblox credential or the rotator URL from the
    dashboard, the new value cannot be written to `/etc/roxy/credentials`. It is stored in control.db instead,
    encrypted, so a copied database file or backup does not reveal it. This protects against exfiltration of the
    file only; on the running host the key and the process memory are reachable (plan 9.8 says so plainly).

How it works
    AES-256-GCM with a fresh random 12-byte nonce per seal. The "associated data" names the table the ciphertext
    belongs to (`roxy:credential_store:v1`, `roxy:rotator_store:v1`), so a ciphertext copied from one table into
    the other fails to decrypt instead of being accepted. The key file may hold 64 hex characters, base64 of 32
    bytes, or 32 raw bytes. The key's hex form is registered with the log redactor.

What to read next
    `roxy/egress/credential.py` (`credential_store`) and `roxy/egress/rotator.py` (`rotator_store`).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import secrets
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from roxy.core.redact import SecretRegistry
from roxy.egress.errors import EgressConfigError

KEY_FILE_NAME = "credential_encryption_key"
"""The systemd credential holding the key (plan 9.8)."""

KEY_BYTES = 32
NONCE_BYTES = 12
_MAX_KEY_FILE_BYTES = 256


class SealError(ValueError):
    """A sealed value could not be opened (wrong key, wrong table, or a damaged row)."""


def _decode_key(raw: bytes) -> bytes:
    text = raw.strip()
    if len(text) == 2 * KEY_BYTES:
        try:
            return binascii.unhexlify(text)
        except binascii.Error:
            pass
    try:
        decoded = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        decoded = b""
    if len(decoded) == KEY_BYTES:
        return decoded
    if len(raw) == KEY_BYTES:
        return raw
    raise EgressConfigError(f"{KEY_FILE_NAME} must hold 32 bytes (64 hex characters, base64, or raw bytes)")


def load_encryption_key(credentials_dir: Path | None) -> bytes | None:
    """The 32-byte key, or None when the credential is not configured (UI replacement is then unavailable)."""
    if credentials_dir is None:
        return None
    path = Path(credentials_dir) / KEY_FILE_NAME
    try:
        with path.open("rb") as handle:
            raw = handle.read(_MAX_KEY_FILE_BYTES + 1)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise EgressConfigError(f"{KEY_FILE_NAME} exists but cannot be read ({type(exc).__name__})") from exc
    if len(raw) > _MAX_KEY_FILE_BYTES:
        raise EgressConfigError(f"{KEY_FILE_NAME} is too large to be a key")
    key = _decode_key(raw)
    SecretRegistry.register(KEY_FILE_NAME, key.hex())
    return key


def derive_key(key: bytes, label: bytes) -> bytes:
    """A 32-byte sub-key for one purpose (HMAC-SHA256 of `label` under `key`), so one key never serves two jobs."""
    return hmac.new(key, label, hashlib.sha256).digest()


def seal(key: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    """Encrypt `plaintext` for the table named by `aad`. Returns `(nonce, ciphertext)`."""
    nonce = secrets.token_bytes(NONCE_BYTES)
    return nonce, AESGCM(key).encrypt(nonce, plaintext, aad)


def unseal(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    """Decrypt a sealed value, or raise `SealError` (never returns garbage: GCM authenticates the ciphertext)."""
    if len(nonce) != NONCE_BYTES:
        raise SealError("bad nonce length")
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise SealError("the stored value does not decrypt with this key") from exc


__all__ = ["KEY_FILE_NAME", "SealError", "derive_key", "load_encryption_key", "seal", "unseal"]
