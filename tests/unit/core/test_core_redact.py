"""Redaction tests (plan 9.15 and 19.1 "redaction (every secret form)"): every secret shape leaves no trace."""

from __future__ import annotations

import secrets

import pytest

from roxy.core.redact import (
    MASK,
    MIN_SECRET_LENGTH,
    TOKEN_PREFIX,
    SecretRegistry,
    fingerprint,
    is_sensitive_key,
    mask_token,
    masked_url,
    redact_headers,
    redact_query,
    redact_text,
)

ELLIPSIS = chr(0x2026)


def fake_credential() -> str:
    return TOKEN_PREFIX + "FAKE" + secrets.token_hex(120).upper()


# --- v1 formats ----------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("ABCDEF0123456789", ELLIPSIS + "456789"),
        ("abc", ELLIPSIS + "abc"),
        ("", ELLIPSIS),
        (None, ELLIPSIS),
    ],
)
def test_mask_token_matches_v1_format(value: str | None, expected: str) -> None:
    # v1 proxy.mask_token: f"…{(token or '')[-6:]}"
    assert mask_token(value) == expected


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("http://user:pass@gw.example.test:823", "http://gw.example.test:823"),
        ("https://user-country-us:p4ss@gw.example.test:10000", "https://gw.example.test:10000"),
        ("http://gw.example.test:823", "http://gw.example.test:823"),
        ("user:pass@gw.example.test:823", ""),  # v1 returned "" for a credentialed value without a scheme
        ("", ""),
        (None, ""),
    ],
)
def test_masked_url_matches_v1(url: str | None, expected: str) -> None:
    assert masked_url(url) == expected


def test_masked_url_never_leaks_a_password_containing_at_sign() -> None:
    masked = masked_url("http://user:se@cret@gw.example.test:823")
    assert masked == "http://gw.example.test:823"
    assert "cret" not in masked


# --- registry ------------------------------------------------------------------------------------------------------


def test_registered_secret_is_redacted() -> None:
    value = "smtp-" + secrets.token_hex(8)
    SecretRegistry.register("smtp_password", value)
    out = redact_text(f"login failed for owner with {value} at step 2")
    assert value not in out
    assert MASK in out


def test_short_values_are_not_registered() -> None:
    SecretRegistry.register("tiny", "a" * (MIN_SECRET_LENGTH - 1))
    assert SecretRegistry.names() == []
    assert redact_text("aaaaaaa") == "aaaaaaa"


def test_replaced_secret_stays_hidden() -> None:
    old, new = "old-" + secrets.token_hex(8), "new-" + secrets.token_hex(8)
    SecretRegistry.register("rotator_url", old)
    SecretRegistry.register("rotator_url", new)
    assert old not in redact_text(f"was {old} now {new}")
    assert new not in redact_text(f"was {old} now {new}")


def test_credential_substring_of_24_chars_is_redacted() -> None:
    credential = fake_credential()
    SecretRegistry.register("roblox_credential", credential)
    secret_part = credential[len(TOKEN_PREFIX) :]
    chunk = secret_part[37 : 37 + 24]
    out = redact_text(f"x={chunk}!")
    assert chunk not in out
    assert out == f"x={MASK}!"


def test_credential_long_substring_redacted_whole() -> None:
    credential = fake_credential()
    SecretRegistry.register("roblox_credential", credential)
    secret_part = credential[len(TOKEN_PREFIX) :]
    chunk = secret_part[10:200]
    out = redact_text(f"body: {chunk} end")
    assert out == f"body: {MASK} end"


def test_credential_substring_shorter_than_24_is_kept() -> None:
    credential = fake_credential()
    SecretRegistry.register("roblox_credential", credential)
    chunk = credential[len(TOKEN_PREFIX) + 5 : len(TOKEN_PREFIX) + 5 + 23]
    assert redact_text(chunk) == chunk


def test_other_secrets_do_not_match_by_substring() -> None:
    value = "webhook-" + secrets.token_hex(20)
    SecretRegistry.register("alert_webhook_url", value)
    part = value[3:30]
    assert redact_text(part) == part  # only the credential is matched by substrings


# --- shapes --------------------------------------------------------------------------------------------------------


def test_token_prefix_and_value_redacted() -> None:
    cookie = TOKEN_PREFIX + "ABCDEF1234567890ABCDEF"
    out = redact_text(f"cookie value {cookie}; next=1")
    assert "WARNING:-DO-NOT-SHARE-THIS" not in out
    assert "ABCDEF1234567890ABCDEF" not in out
    assert out.endswith("; next=1")


def test_roblosecurity_cookie_redacted() -> None:
    out = redact_text("Sent .ROBLOSECURITY=deadbeefcafe12345; Path=/")
    assert "deadbeefcafe12345" not in out
    assert ".ROBLOSECURITY=" + MASK in out


def test_url_userinfo_redacted() -> None:
    out = redact_text("proxy http://user-zone:hunter2pass@gw.example.test:823 failed")
    assert "hunter2pass" not in out
    assert "user-zone" not in out
    assert "gw.example.test:823" in out


def test_url_userinfo_with_at_sign_in_password_redacted() -> None:
    out = redact_text("proxy http://user:pa@ss@gw.example.test:823/x failed")
    assert "pa@ss" not in out
    assert "ss@gw" not in out


@pytest.mark.parametrize("name", ["Cookie", "Set-Cookie", "Authorization", "X-CSRF-Token", "Proxy-Authorization"])
def test_secret_header_lines_redacted(name: str) -> None:
    out = redact_text(f"GET / HTTP/1.1\n{name}: Bearer abc.def.ghi\nAccept: */*")
    assert "abc.def.ghi" not in out
    assert "Accept: */*" in out


@pytest.mark.parametrize(
    "text",
    [
        '{"password": "correct horse battery staple"}',
        "{'new_password': 'correct horse battery staple'}",
        "password=correct+horse&user=owner",
        "totp_code=123456",
        "recovery_code: ABCD-EFGH",
        '"email_code":"654321"',
        "x-csrf-token=abcdef0123456789",
        "admin_session_id=0123456789abcdef",
        "csrf_token=0123456789abcdef",
        "otp=123456",
    ],
)
def test_secret_named_fields_redacted(text: str) -> None:
    out = redact_text(text)
    secrets_in_inputs = ("correct horse battery staple", "correct+horse", "123456", "ABCD-EFGH", "654321")
    for secret in (*secrets_in_inputs, "0123456789abcdef"):
        assert secret not in out
    assert MASK in out


@pytest.mark.parametrize(
    "text",
    [
        "bypass=1",
        "cache_key=games.roblox.com/v1/games",
        "status=429",
        "credential_status=ok",
        "reason_code=deadline",
        "tokens_left=12",
    ],
)
def test_ordinary_fields_kept(text: str) -> None:
    assert redact_text(text) == text


@pytest.mark.parametrize(
    ("name", "sensitive"),
    [
        ("password", True),
        ("Password", True),
        ("new-password", True),
        ("pass", True),
        ("user_pass", True),
        ("bypass", False),
        ("X-CSRF-Token", True),
        ("cookie", True),
        ("set-cookie", True),
        ("api_key", True),
        ("cache_key", False),
        ("session", True),
        ("__Host-roxy_session", True),
        ("sessions_revoked", False),
        ("ip_hash_key", True),
        ("user-agent", False),
        ("x-roblox-token", True),
    ],
)
def test_is_sensitive_key(name: str, sensitive: bool) -> None:
    assert is_sensitive_key(name) is sensitive


def test_redact_query_keeps_structure() -> None:
    out = redact_query("universeIds=1,2&password=hunter2&token=abc123&limit=10")
    assert out == f"universeIds=1,2&password={MASK}&token={MASK}&limit=10"


def test_redact_query_scrubs_registered_values() -> None:
    value = "smtp-" + secrets.token_hex(8)
    SecretRegistry.register("smtp_password", value)
    assert value not in redact_query(f"q={value}")


def test_redact_headers_mapping_pairs_and_bytes() -> None:
    credential = fake_credential()
    SecretRegistry.register("roblox_credential", credential)
    mapping = {"Cookie": "a=b", "User-Agent": "Roblox/WinInet", "X-Note": credential[len(TOKEN_PREFIX) :][:40]}
    out = redact_headers(mapping)
    assert out["Cookie"] == MASK
    assert out["User-Agent"] == "Roblox/WinInet"
    assert out["X-Note"] == MASK
    raw = [(b"authorization", b"Bearer x"), (b"accept", b"application/json")]
    assert redact_headers(raw) == {"authorization": MASK, "accept": "application/json"}
    assert redact_headers({"X-Long": "v" * 5000}, max_value_length=2000)["X-Long"] == "v" * 2000


def test_fingerprint_is_keyed_and_stable() -> None:
    key_a, key_b = secrets.token_bytes(32), secrets.token_bytes(32)
    assert fingerprint("value", key_a) == fingerprint(b"value", key_a)
    assert fingerprint("value", key_a) != fingerprint("value", key_b)
    assert len(fingerprint("value", key_a)) == 16
    int(fingerprint("value", key_a), 16)  # hex


# --- fix pass: security review M1, M2, M3, L1, L2, L5 ------------------------------------------------------------


def test_registering_the_credential_keeps_the_token_prefix_rule() -> None:
    """M1: the credential's windows used to include the public prefix, eat it, and switch the prefix rule off."""
    caller_value = "C0FFEE" + secrets.token_hex(80).upper()  # a caller's own cookie, not Roxy's
    line = f"GET /auth.roblox.com/v1/x/{TOKEN_PREFIX}{caller_value}"
    SecretRegistry.register("roblox_credential", fake_credential())
    out = redact_text(line)
    assert caller_value not in out
    assert caller_value[:24] not in out
    assert out.startswith("GET /auth.roblox.com/v1/x/")


def test_lowercased_credential_is_still_redacted() -> None:
    """L2: hex case is trivially reversible, so the 24 character windows ignore ASCII case."""
    credential = fake_credential()
    SecretRegistry.register("roblox_credential", credential)
    secret_part = credential[len(TOKEN_PREFIX) :]
    assert secret_part.lower()[5:60] not in redact_text(f"path={secret_part.lower()[5:60]}")
    assert secret_part[5:60] not in redact_text(f"path={secret_part[5:60]}")


@pytest.mark.parametrize("double", [False, True])
def test_percent_encoded_markers_are_redacted(double: bool) -> None:
    """M2: an encoded TOKEN_PREFIX or `.ROBLOSECURITY=` must not carry a value past redaction."""
    from urllib.parse import quote

    other_cookie = "FAKEOTHER" + secrets.token_hex(60).upper()

    def encode(text: str) -> str:
        once = quote(text, safe="")
        return quote(once, safe="") if double else once

    for raw in (TOKEN_PREFIX + other_cookie, ".ROBLOSECURITY=" + other_cookie):
        query = "limit=10&x=" + encode(raw)
        assert other_cookie[:20] not in redact_query(query), raw[:20]
        assert other_cookie[:20] not in redact_text("/games.roblox.com/v1/a?" + query), raw[:20]
        assert redact_query(query).startswith("limit=10&")
    credential = fake_credential()
    SecretRegistry.register("roblox_credential", credential)
    assert credential[-40:] not in redact_text("q=" + encode(credential))
    # Ordinary encoded values are left alone (structure kept for debugging).
    assert redact_query("q=caf%C3%A9&ids=1%2C2") == "q=caf%C3%A9&ids=1%2C2"


@pytest.mark.parametrize("name", ["X-Api-Key", "x-api-key", "API-KEY", "X-Access-Key", "private-key"])
def test_api_key_headers_are_secret(name: str) -> None:
    """M3: Roblox Open Cloud sends its API keys in X-Api-Key."""
    assert is_sensitive_key(name)
    assert redact_headers([(name.encode(), b"k" * 10)]) == {name: MASK}


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ('{"code": "123456"}', "123456"),
        ("code=123456", "123456"),
        ('{"TwoFA": "112233"}', "112233"),
        ('{"mfa": "445566"}', "445566"),
        ('{"recovery": "abcd-efgh-ijkl"}', "abcd-efgh-ijkl"),
        ('{"passcode": "778899"}', "778899"),
        ("[(b'x-csrf-token', b'abcdefabcdefabcdef'), (b'accept', b'*/*')]", "abcdefabcdefabcdef"),
        ("[('authorization', 'Bearer tok123tok123')]", "tok123tok123"),
        ("(b'cookie', b'.ROBLOSECURITY=zzzzzzzzzz')", "zzzzzzzzzz"),
    ],
)
def test_code_fields_and_header_reprs_are_redacted(text: str, secret: str) -> None:
    """L1: one-time code fields under their bare names, and header pairs printed as a Python repr."""
    out = redact_text(text)
    assert secret not in out
    assert MASK in out


def test_harmless_header_repr_is_kept() -> None:
    text = "[(b'accept', b'application/json'), (b'user-agent', b'Roblox/WinInet')]"
    assert redact_text(text) == text


def test_kill_switch_token_never_reaches_a_log_line() -> None:
    """L5: `/admin/invalidate/<token>` keeps its token in the path (plan D9)."""
    token = secrets.token_urlsafe(32)
    for text in (f"/admin/invalidate/{token}", f"GET /admin/invalidate/{token}?x=1 HTTP/1.1"):
        out = redact_text(text)
        assert token not in out
        assert "/admin/invalidate/" + MASK in out


def test_redaction_stays_fast_on_hostile_text() -> None:
    import time

    hostile = [
        "(b'authorization', b'" + "\\" * 8000,
        "%" * 8000,
        "%25" * 2700,
        TOKEN_PREFIX[:60] * 130,
        "a=" * 4000,
    ]
    SecretRegistry.register("roblox_credential", fake_credential())
    for text in hostile:
        started = time.perf_counter()
        redact_text(text)
        redact_query(text)
        assert time.perf_counter() - started < 0.25, text[:30]


def test_roblox_error_codes_stay_readable() -> None:
    """A bare `code` is secret only when shaped like a one-time code: Roblox's error codes are small numbers."""
    from roxy.core.redact import is_secret_field

    body = '{"errors":[{"code":0,"message":"Too many requests"}]}'
    assert redact_text(body) == body
    assert redact_text("code=17") == "code=17"
    assert not is_secret_field("code", 429)
    assert is_secret_field("code", 123456)
    assert is_secret_field("code", "abcd-efgh-ijkl")
    assert is_secret_field("password", "")


# --- labels (finding F4) -------------------------------------------------------------------------------------------


def test_redact_label_keeps_ordinary_labels_exactly() -> None:
    """Endpoint templates, hosts and place ids that hold no secret come back unchanged (v1 templating parity)."""
    from roxy.core.redact import redact_label

    SecretRegistry.register("roblox_credential", fake_credential())
    for label in (
        "games.roblox.com/v1/games/{gameId}/servers/Public",
        "avatar.roblox.com/v2/avatar/users/{userId}/outfits",
        "thumbnails.roblox.com",
        "1818",
        "(not_roblox)",
        "",
    ):
        assert redact_label(label) == label


def test_redact_label_scrubs_a_credential_piece_and_markers() -> None:
    from roxy.core.redact import redact_label

    credential = fake_credential()
    SecretRegistry.register("roblox_credential", credential)
    piece = credential[len(TOKEN_PREFIX) + 30 : len(TOKEN_PREFIX) + 70]
    assert piece not in redact_label(f"games.roblox.com/v1/x.{piece}")
    assert piece.lower() not in redact_label(f"{piece.lower()}.roblox.com")
    assert piece not in redact_label(piece)  # a Roblox-Id header holding only the piece
    assert redact_label(piece) == MASK
    assert redact_label(f"games.roblox.com/v1/{TOKEN_PREFIX}abc") == f"games.roblox.com/v1/{MASK}"


def test_redact_label_memory_follows_the_registry() -> None:
    """An answer remembered before a secret was registered is never reused after: a label that was clean must be
    scrubbed once it holds a piece of the newly registered credential (a replace)."""
    from roxy.core.redact import redact_label

    credential = fake_credential()
    piece = credential[len(TOKEN_PREFIX) + 10 : len(TOKEN_PREFIX) + 50]
    label = f"games.roblox.com/v1/x.{piece}"
    assert redact_label(label) == label  # nothing registered yet: an ordinary label, remembered
    SecretRegistry.register("roblox_credential", credential)
    assert piece not in redact_label(label)


def test_redact_label_memory_is_bounded() -> None:
    from roxy.core import redact

    cache = redact._LabelCache(4)
    for n in range(50):
        assert cache.redact(f"label-{n}") == f"label-{n}"
        assert len(cache._state[1]) <= 4
    long_text = "x" * (redact.LABEL_CACHE_MAX_CHARS + 1)
    assert cache.redact(long_text) == long_text
    assert long_text not in cache._state[1]  # long texts are redacted every time, never remembered
