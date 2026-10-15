"""TOTP (plan 9.5, 9.8): RFC 6238 steps, the +/- 1 window, the encrypted secret, enrollment QR codes."""

from __future__ import annotations

import os
from pathlib import Path

import pyotp
import pytest

from roxy.admin.auth import totp


def test_match_step_finds_the_current_and_adjacent_steps_only() -> None:
    secret = totp.new_secret()
    now = 1_760_000_015.0
    step = totp.current_step(now)
    for offset in (-1, 0, 1):
        assert totp.match_step(secret, totp.code_for_step(secret, step + offset), now) == step + offset
    for offset in (-2, 2):
        assert totp.match_step(secret, totp.code_for_step(secret, step + offset), now) is None


def test_codes_match_a_standard_authenticator() -> None:
    secret = totp.new_secret()
    now = 1_760_000_000.0
    assert totp.code_at(secret, now) == pyotp.TOTP(secret).at(now)


@pytest.mark.parametrize("code", ["", "12345", "1234567", "12345a", "١٢٣٤٥٦", "      "])
def test_malformed_codes_never_match(code: str) -> None:
    assert totp.match_step(totp.new_secret(), code, 1_760_000_000.0) is None


def test_corrupt_secret_is_a_wrong_code_not_an_error() -> None:
    assert totp.match_step("not base32 !!!", "123456", 1_760_000_000.0) is None


def test_cipher_round_trip_and_binding() -> None:
    cipher = totp.TotpCipher(os.urandom(32))
    secret = totp.new_secret()
    blob = cipher.encrypt(secret, totp.user_context(7))
    assert secret.encode() not in blob
    assert cipher.decrypt(blob, totp.user_context(7)) == secret
    assert cipher.decrypt(blob, totp.user_context(8)) is None  # bound to its admin
    tampered = blob[:-1] + bytes([blob[-1] ^ 1])
    assert cipher.decrypt(tampered, totp.user_context(7)) is None
    assert totp.TotpCipher(os.urandom(32)).decrypt(blob, totp.user_context(7)) is None
    assert cipher.decrypt(b"\x02" + blob[1:], totp.user_context(7)) is None


def test_cipher_needs_a_32_byte_key() -> None:
    with pytest.raises(totp.TotpKeyMissing):
        totp.TotpCipher(b"short")


def test_load_key_from_the_credentials_directory(credentials_dir: Path, tmp_path: Path) -> None:
    key = totp.load_totp_key(credentials_dir)
    assert key is not None
    assert len(key) == 32
    assert totp.load_cipher(credentials_dir) is not None
    assert totp.load_totp_key(None) is None
    assert totp.load_totp_key(tmp_path) is None
    (tmp_path / totp.TOTP_KEY_NAME).write_text("too short")
    assert totp.load_totp_key(tmp_path) is None


def test_provisioning_uri_and_qr_codes() -> None:
    secret = totp.new_secret()
    uri = totp.provisioning_uri(secret, "owner")
    assert uri.startswith("otpauth://totp/Roxy:owner?secret=")
    assert "issuer=Roxy" in uri
    assert "digits=6" in uri
    assert "period=30" in uri
    assert totp.qr_svg_data_uri(uri).startswith("data:image/svg+xml")
    art = totp.qr_terminal(uri)
    assert len(art.splitlines()) > 10
