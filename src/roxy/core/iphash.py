"""Client IP hashing: a keyed hash that lets logs and exports correlate callers without storing their IP.

What this is
    `ip_hash(ip, key)` returns the first 16 hex characters of HMAC-SHA256(key, normalized ip).
    `load_ip_hash_key(credentials_dir)` reads the `ip_hash_key` systemd credential, and `derived_key(key, context)`
    makes a per-purpose key (for example one per LLM export) from it.

Why it exists
    Plan 9.15 and 12.3. A plain SHA-256 of an IPv4 address protects nothing: there are only 4 billion addresses, so
    a laptop can hash them all in seconds and reverse any hash. An HMAC with a secret key cannot be reversed
    without the key, which lives only in `$CREDENTIALS_DIRECTORY`, never in the database or backups. Truncating
    to 16 hex characters (64 bits) keeps hashes short while collisions stay negligible for this many callers.

How it works
    The address is normalized first (so `::ffff:1.2.3.4` and `1.2.3.4` hash the same), then HMAC'd. Exports use
    `derived_key(key, "export:<id>")`, so hashes in two different exports do not correlate with each other or
    with the logs unless the owner sets `export_stable_ip_hash` = 1. Rotating the key yearly stops old hashes from
    correlating with new ones, by design.

What to read next
    `roxy/core/logging.py` (`set_ip_hasher`, used when `log_hash_client_ips` = 1), then
    `roxy/insights/llm_export.py`.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
from pathlib import Path

from roxy.core.client_ip import normalize_ip

IP_HASH_KEY_NAME = "ip_hash_key"
"""File name of the systemd credential that holds the key (plan 9.8)."""

MIN_KEY_BYTES = 16


def ip_hash(ip: str, key: bytes) -> str:
    """HMAC-SHA256 of the normalized address, first 16 hex characters."""
    if not key:
        raise ValueError("ip_hash needs a non-empty key")
    text = normalize_ip(ip) or ip.strip()
    return hmac.new(key, text.encode("utf-8"), hashlib.sha256).hexdigest()[:16]


def derived_key(key: bytes, context: str) -> bytes:
    """A key for one purpose (for example `export:<id>`), derived from the main key with HMAC-SHA256."""
    return hmac.new(key, b"roxy-derived:" + context.encode("utf-8"), hashlib.sha256).digest()


def decode_key_material(raw: bytes) -> bytes:
    """Turn the bytes of a key file into key bytes.

    Accepts 64 hex characters (what `openssl rand -hex 32` writes), base64 of 32 bytes (`openssl rand -base64
    32`), or raw random bytes; surrounding whitespace is ignored for the text forms.
    """
    text = raw.strip()
    if len(text) == 64:
        try:
            return binascii.unhexlify(text)
        except (binascii.Error, ValueError):
            pass
    if len(text) == 44 and text.endswith(b"="):
        try:
            decoded = base64.b64decode(text, validate=True)
        except (binascii.Error, ValueError):
            decoded = b""
        if len(decoded) == 32:
            return decoded
    return raw


def load_ip_hash_key(credentials_dir: Path | None) -> bytes | None:
    """Read the `ip_hash_key` credential, or None when the directory or file is missing or the key is too short.

    Missing is normal in development; the caller logs that IP hashing is unavailable instead of failing.
    """
    if credentials_dir is None:
        return None
    path = credentials_dir / IP_HASH_KEY_NAME
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    key = decode_key_material(raw)
    if len(key) < MIN_KEY_BYTES:
        return None
    return key
