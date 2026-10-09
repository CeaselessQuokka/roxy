"""Review round 3 (lens apisec): the fresh second factor (plan 9.6) and the settings API.

What this is
    Strict-xfail tests for finding apisec-1. The settings API (`PATCH /settings`, `PUT /settings/{key}`, import,
    history revert) changes every catalog setting with a session and a CSRF token only, including the
    `admin_security` group. One of those settings is `admin_reauth_window_s` itself (60 to 3600 s): a session whose
    second factor went stale can raise the window and become "fresh" again, then pass every `fresh_mfa` guard
    (recovery code regeneration, passkeys, credential replace, rotator URL, factory reset, the admin allowlist,
    spam arming). Another is `admin_allowlist_enabled`: the allowlist entries need a fresh second factor
    (`/protection/access/allow_admin`), but switching the whole allowlist off does not.

Why it exists
    Plan 9.6 puts a fresh second factor in front of sensitive actions so that someone using an unlocked or stolen
    session cannot take the account over. The recommendations API already treats a change of an `admin_security`
    or `credential` setting as needing a fresh factor (`recommendations.SENSITIVE_GROUPS`), so the same change made
    through the settings editor is the bypass.

How it works
    The `api` fixture signs in with password and TOTP. The clock is moved just past `admin_reauth_window_s` (the
    session stays alive: 601 s is inside the 900 s idle timeout); a regeneration of recovery codes is refused with
    403 `reauth_required` as it should be. Then the stale session asks the settings API for the change, and the
    sensitive route is tried again.

What to read next
    `roxy/admin/api/settings.py` (`update_settings`, `set_setting`), `roxy/admin/auth/sessions.py`
    (`SessionRecord.is_fresh`), `roxy/admin/api/recommendations.py` (`SENSITIVE_GROUPS`, `_sensitive`).
"""

from __future__ import annotations

from typing import Any

import pytest

REGENERATE = "security/recovery-codes/regenerate"


def _code(response: Any) -> str | None:
    try:
        body = response.json()
    except ValueError:
        return None
    error = body.get("error") if isinstance(body, dict) else None
    return error.get("code") if isinstance(error, dict) else None


async def _stale(api: Any) -> None:
    api.make_mfa_stale()
    refused = await api.post(REGENERATE, json={})
    assert refused.status_code == 403, refused.text
    assert _code(refused) == "reauth_required"


@pytest.mark.xfail(
    strict=True,
    reason="finding apisec-1: a stale session raises admin_reauth_window_s via PATCH /settings and becomes fresh",
)
async def test_a_stale_session_cannot_refresh_itself_through_the_settings_api(api: Any, api_app: Any) -> None:
    await _stale(api)
    window = int(api_app.ctx.settings.int("admin_reauth_window_s"))
    patch = await api.patch(
        "settings",
        json={
            "changes": {"admin_reauth_window_s": 3600},
            "reason": "longer window",
            "confirm_high_risk": True,
        },
    )
    await api_app.ctx.settings.reload()  # what the config watcher does within a second
    after = await api.post(REGENERATE, json={})
    assert (patch.status_code, _code(patch)) == (403, "reauth_required"), (
        f"PATCH admin_reauth_window_s {window} -> 3600 with a stale second factor answered {patch.status_code}; "
        f"regenerating recovery codes then answered {after.status_code}"
    )
    assert after.status_code == 403, after.text[:200]


@pytest.mark.xfail(
    strict=True,
    reason="finding apisec-1: the admin allowlist is switched off with a stale session though its entries need MFA",
)
async def test_the_admin_allowlist_switch_needs_the_same_fresh_factor_as_its_entries(api: Any, api_app: Any) -> None:
    await api_app.harness.allow_admin_cidr("127.0.0.0/8")  # the test client's address, so the admin keeps access
    await api_app.settings(admin_allowlist_enabled=1)
    await _stale(api)
    entries = await api.get("protection/access/allow_admin")
    assert entries.status_code == 200, entries.text
    entry_id = entries.json()["items"][0]["id"]
    removed = await api.delete(f"protection/access/allow_admin/{entry_id}", params={"confirm_lockout": "true"})
    assert (removed.status_code, _code(removed)) == (403, "reauth_required")  # the entry route asks for the factor
    switched = await api.put("settings/admin_allowlist_enabled", json={"value": 0, "reason": "off"})
    assert (switched.status_code, _code(switched)) == (403, "reauth_required"), switched.text[:200]
