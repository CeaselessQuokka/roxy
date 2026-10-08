"""Small parts: CSRF masking and origin rules, session rows, trusted device families, short-lived records."""

from __future__ import annotations

import secrets
from typing import Any

from starlette.requests import Request

from roxy.admin.auth import csrf, sessions, transactions, trusted_devices, users


def _request(headers: dict[str, str]) -> Request:
    raw = [(k.lower().encode(), v.encode()) for k, v in headers.items()]
    return Request({"type": "http", "method": "POST", "path": "/admin/api/v1/x", "headers": raw, "query_string": b""})


def test_mask_is_fresh_every_time_and_round_trips() -> None:
    secret = secrets.token_bytes(32)
    masks = {csrf.mask(secret) for _ in range(50)}
    assert len(masks) == 50  # never the same string twice (BREACH)
    assert all(csrf.unmask(m) == secret for m in masks)
    for bad in ("", "abc", "!" * 60, csrf.mask(secret)[:-4], "a" * 500):
        assert csrf.unmask(bad) is None


def test_same_origin_rules() -> None:
    site = "https://roxy.example"
    assert csrf.same_origin_problem(_request({"Origin": site}), site) is None
    assert csrf.same_origin_problem(_request({"Sec-Fetch-Site": "same-origin"}), site) is None
    assert csrf.same_origin_problem(_request({"Origin": "https://evil.example"}), site) == "origin_mismatch"
    assert csrf.same_origin_problem(_request({"Sec-Fetch-Site": "cross-site"}), site) == "cross_site_fetch"
    assert csrf.same_origin_problem(_request({"Sec-Fetch-Site": "same-site"}), site) == "cross_site_fetch"
    assert csrf.same_origin_problem(_request({}), site) == "no_origin_headers"
    secret = secrets.token_bytes(32)
    good = {"Origin": site, csrf.CSRF_HEADER: csrf.mask(secret)}
    assert csrf.check(_request(good), secret, site) is None
    assert csrf.check(_request({"Origin": site}), secret, site) == "missing_token"
    assert csrf.check(_request({**good, csrf.CSRF_HEADER: "zz"}), secret, site) == "malformed_token"
    other = csrf.mask(secrets.token_bytes(32))
    assert csrf.check(_request({**good, csrf.CSRF_HEADER: other}), secret, site) == "wrong_token"


def test_csrf_secret_is_derived_and_changes_with_the_session() -> None:
    a, b = sessions.new_token(), sessions.new_token()
    assert sessions.csrf_secret(a) == sessions.csrf_secret(a)
    assert sessions.csrf_secret(a) != sessions.csrf_secret(b)
    assert len(sessions.csrf_secret(a)) == 32


def _user(dbs: Any, name: str = "owner") -> int:
    return int(dbs.control.write_sync(lambda c: users.insert_user(c, username=name, password_hash="x", now=1)))


def test_session_rows_store_only_hashes_and_follow_the_rules(dbs: Any) -> None:
    uid = _user(dbs)
    token, id_hash = dbs.control.write_sync(
        lambda c: sessions.create(c, user_id=uid, ip="1.2.3.4", ua="UA", mfa_level="totp", now=1000, max_age_s=43200)
    )
    assert id_hash == sessions.hash_token(token)
    stored = dbs.control.read_sync(
        lambda c: c.execute("SELECT id_hash, csrf_secret_hash FROM admin_sessions").fetchall()
    )
    assert token not in str(stored)
    record, epoch = dbs.control.read_sync(lambda c: sessions.load(c, id_hash))
    assert sessions.is_live(record, epoch, 1000 + 900, 900)
    assert not sessions.is_live(record, epoch, 1000 + 901, 900)  # idle
    assert not sessions.is_live(record, epoch + 1, 1001, 900)  # kill switch epoch
    assert record.is_fresh(1000 + 600, 600)
    assert not record.is_fresh(1000 + 601, 600)

    new_token, new_hash = dbs.control.write_sync(
        lambda c: sessions.rotate(c, record, mfa_level="passkey", now=5000, ip="1.2.3.4", ua="UA", max_age_s=43200)
    )
    assert dbs.control.read_sync(lambda c: sessions.load(c, id_hash)) is None
    rotated, _ = dbs.control.read_sync(lambda c: sessions.load(c, new_hash))
    assert rotated.expires_at == record.expires_at  # absolute lifetime kept across rotation
    assert rotated.created_at == 5000
    assert rotated.mfa_level == "passkey"
    assert new_token != token

    deleted, new_epoch = dbs.control.write_sync(lambda c: sessions.revoke_all(c, 6000))
    assert deleted == 1
    assert new_epoch == epoch + 1


def test_sessions_are_capped_per_admin(dbs: Any) -> None:
    uid = _user(dbs)
    for i in range(sessions.MAX_SESSIONS_PER_USER + 5):
        dbs.control.write_sync(
            lambda c, n=i: sessions.create(c, user_id=uid, ip=None, ua=None, mfa_level="totp", now=n, max_age_s=600)
        )
    count = dbs.control.read_sync(lambda c: c.execute("SELECT count(*) FROM admin_sessions").fetchone()[0])
    assert count == sessions.MAX_SESSIONS_PER_USER


def test_bootstrap_sessions_are_short(dbs: Any) -> None:
    uid = _user(dbs)
    _, id_hash = dbs.control.write_sync(
        lambda c: sessions.create(c, user_id=uid, ip=None, ua=None, mfa_level="bootstrap", now=0, max_age_s=43200)
    )
    record, _ = dbs.control.read_sync(lambda c: sessions.load(c, id_hash))
    assert record.expires_at == sessions.BOOTSTRAP_MAX_AGE_S


def test_ua_family_ignores_versions_but_not_browsers() -> None:
    cases = {
        "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0": "firefox/linux",
        "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0": "firefox/linux",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/128.0 Safari/537.36": "chrome/windows",
        "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/128.0 Safari/537.36 Edg/128.0": "edge/windows",
        "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/128.0 Mobile Safari/537.36": "chrome/android",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Version/17.0 Safari/604.1": "safari/ios",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) Version/17.0 Safari/605.1.15": "safari/macos",
        "curl/8.0": "other/other",
        "": "other/other",
    }
    for ua, family in cases.items():
        assert trusted_devices.ua_family(ua) == family, ua
    assert trusted_devices.device_name(next(iter(cases))) == "Firefox on Linux"


def test_trusted_device_rows(dbs: Any) -> None:
    uid = _user(dbs)
    ua = "Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0"
    token = dbs.control.write_sync(lambda c: trusted_devices.issue(c, user_id=uid, ua=ua, now=1000, days=30))
    assert dbs.control.read_sync(lambda c: trusted_devices.find_valid(c, token, ua, 2000)) is not None
    assert dbs.control.read_sync(lambda c: trusted_devices.find_valid(c, token, "curl/8", 2000)) is None
    assert dbs.control.read_sync(lambda c: trusted_devices.find_valid(c, token, ua, 1000 + 30 * 86400)) is None
    assert dbs.control.read_sync(lambda c: trusted_devices.find_valid(c, "nope", ua, 2000)) is None
    stored = dbs.control.read_sync(lambda c: c.execute("SELECT token_hash FROM trusted_devices").fetchall())
    assert token not in str(stored)
    for i in range(trusted_devices.MAX_DEVICES_PER_USER + 3):
        dbs.control.write_sync(lambda c, n=i: trusted_devices.issue(c, user_id=uid, ua=ua, now=2000 + n, days=30))
    assert (
        len(dbs.control.read_sync(lambda c: trusted_devices.list_for_user(c, uid, 3000)))
        == trusted_devices.MAX_DEVICES_PER_USER
    )
    assert dbs.control.write_sync(lambda c: trusted_devices.revoke_all(c, uid)) == trusted_devices.MAX_DEVICES_PER_USER


def test_short_lived_records(dbs: Any) -> None:
    dbs.hot.write_sync(lambda c: transactions.put(c, "auth_tx:a", {"x": 1}, 2000))
    assert dbs.hot.read_sync(lambda c: transactions.get(c, "auth_tx:a", 1999)) == {"x": 1}
    assert dbs.hot.read_sync(lambda c: transactions.get(c, "auth_tx:a", 2000)) is None
    raw = dbs.hot.read_sync(lambda c: transactions.raw_payload(c, "auth_tx:a"))
    assert dbs.hot.write_sync(lambda c: transactions.take(c, "auth_tx:a", 1000, expect="{}")) is None
    assert dbs.hot.write_sync(lambda c: transactions.take(c, "auth_tx:a", 1000, expect=raw)) == {"x": 1}
    assert dbs.hot.write_sync(lambda c: transactions.take(c, "auth_tx:a", 1000)) is None  # taken once only
    for i in range(10):
        dbs.hot.write_sync(lambda c, n=i: transactions.put(c, f"auth_tx:{n}", {}, 5000 + n))
    assert dbs.hot.write_sync(lambda c: transactions.cap(c, transactions.LOGIN_TX, 1000, limit=4)) == 6
    remaining = dbs.hot.read_sync(lambda c: c.execute("SELECT name FROM lease ORDER BY name").fetchall())
    assert [r[0] for r in remaining if str(r[0]).startswith("auth_tx:")] == [f"auth_tx:{n}" for n in range(6, 10)]


def test_totp_replay_guard(dbs: Any) -> None:
    now_ms = 100 * 30 * 1000
    assert dbs.hot.write_sync(lambda c: transactions.accept_totp_step(c, 1, 100, now_ms))
    assert not dbs.hot.write_sync(lambda c: transactions.accept_totp_step(c, 1, 100, now_ms))
    assert not dbs.hot.write_sync(lambda c: transactions.accept_totp_step(c, 1, 99, now_ms))
    assert dbs.hot.write_sync(lambda c: transactions.accept_totp_step(c, 1, 101, now_ms))
    assert dbs.hot.write_sync(lambda c: transactions.accept_totp_step(c, 2, 100, now_ms))  # per admin
