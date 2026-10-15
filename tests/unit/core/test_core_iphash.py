"""Client IP hashing tests (plan 9.15, 12.3): keyed, normalized, 16 hex characters, keys from the credential."""

from __future__ import annotations

import base64
import secrets
from pathlib import Path

import pytest

from roxy.core.iphash import decode_key_material, derived_key, ip_hash, load_ip_hash_key


def test_ip_hash_is_keyed_truncated_and_normalized() -> None:
    key = secrets.token_bytes(32)
    other = secrets.token_bytes(32)
    value = ip_hash("203.0.113.7", key)
    assert len(value) == 16
    int(value, 16)
    assert ip_hash("203.0.113.7", key) == value
    assert ip_hash("::ffff:203.0.113.7", key) == value  # same caller, same hash
    assert ip_hash("203.0.113.7", other) != value  # without the key, the hash is useless
    assert ip_hash("203.0.113.8", key) != value


def test_ip_hash_needs_a_key() -> None:
    with pytest.raises(ValueError):
        ip_hash("203.0.113.7", b"")


def test_derived_keys_do_not_correlate() -> None:
    key = secrets.token_bytes(32)
    one, two = derived_key(key, "export:1"), derived_key(key, "export:2")
    assert one != two != key
    assert ip_hash("203.0.113.7", one) != ip_hash("203.0.113.7", two)


def test_key_file_formats(tmp_path: Path) -> None:
    raw = secrets.token_bytes(32)
    assert decode_key_material(raw.hex().encode() + b"\n") == raw
    assert decode_key_material(base64.b64encode(raw) + b"\n") == raw
    assert decode_key_material(raw) == raw


def test_load_ip_hash_key(tmp_path: Path) -> None:
    raw = secrets.token_bytes(32)
    (tmp_path / "ip_hash_key").write_text(raw.hex() + "\n", encoding="ascii")
    assert load_ip_hash_key(tmp_path) == raw
    assert load_ip_hash_key(None) is None
    assert load_ip_hash_key(tmp_path / "missing") is None
    (tmp_path / "short").mkdir()
    (tmp_path / "short" / "ip_hash_key").write_bytes(b"tiny")
    assert load_ip_hash_key(tmp_path / "short") is None
