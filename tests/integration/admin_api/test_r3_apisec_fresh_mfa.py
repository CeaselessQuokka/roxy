"""Review round 3 (lens apisec): the fresh second factor (plan 9.6) and the settings API.

What this is
    Tests for finding apisec-1 (fixed; they were strict xfails). The settings API (`PATCH /settings`,
    `PUT /settings/{key}`, reset, import, history revert) changed every catalog setting with a session and a CSRF
    token only, including the `admin_security` group. One of those settings is `admin_reauth_window_s` itself (60
    to 3600 s): a session whose second factor went stale could raise the window and become "fresh" again, then pass
    every `fresh_mfa` guard (recovery code regeneration, passkeys, credential replace, rotator URL, factory reset,
    the admin allowlist, spam arming). Another is `admin_allowlist_enabled`: the allowlist entries need a fresh
    second factor (`/protection/access/allow_admin`), but switching the whole allowlist off did not.
    Now every settings writer asks `settings.needs_fresh_mfa` (the `admin_security` and `credential` groups, a
    sensitive setting, `export_include_ips`) and answers 403 `reauth_required` for a stale factor; ordinary
    settings keep working with a stale factor.

Why it exists
    Plan 9.6 puts a fresh second factor in front of sensitive actions so that someone using an unlocked or stolen
    session cannot take the account over. The recommendations API already treated a change of an `admin_security`
    or `credential` setting as needing a fresh factor (`recommendations.SENSITIVE_GROUPS`), so the same change made
    through the settings editor was the bypass.

How it works
    The `api` fixture signs in with password and TOTP. The clock is moved just past `admin_reauth_window_s` (the
    session stays alive: 601 s is inside the 900 s idle timeout); a regeneration of recovery codes is refused with
    403 `reauth_required` as it should be. Then the stale session asks each settings writer for a change, and the
    sensitive route is tried again; a fresh factor (`POST /auth/reauth`) makes the same change pass.

What to read next
    `roxy/admin/api/settings.py` (`needs_fresh_mfa`, `require_fresh_for`), `roxy/admin/auth/sessions.py`
    (`SessionRecord.is_fresh`), `roxy/admin/api/recommendations.py` (`SENSITIVE_GROUPS`, `_sensitive`).
"""

from __future__ import annotations

from typing import Any

from roxy.admin.api import settings as settings_api
from roxy.config import catalog

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


async def test_every_settings_writer_asks_a_stale_session_for_the_factor(api: Any, api_app: Any) -> None:
    key = "admin_session_idle_timeout_s"
    fresh = await api.put(f"settings/{key}", json={"value": 1200, "reason": "setup"})
    assert fresh.status_code == 200, fresh.text[:200]  # the login itself is a fresh second factor
    history_id = fresh.json()["changed"][0]["history_id"]
    await _stale(api)
    attempts = {
        "PATCH": await api.patch("settings", json={"changes": {key: 1500}, "reason": "r"}),
        "PUT": await api.put(f"settings/{key}", json={"value": 1500, "reason": "r"}),
        "reset": await api.post(f"settings/{key}/reset", json={"reason": "r"}),
        "revert": await api.post(f"settings/history/{history_id}/revert", json={"reason": "r"}),
        "import": await api.post("settings/import", json={"document": {key: 1500}, "reason": "r"}),
        "credential group": await api.put("settings/credential_probe_interval_min", json={"value": 45}),
        "export_include_ips": await api.put(
            "settings/export_include_ips", json={"value": 1, "reason": "r", "confirm_high_risk": True}
        ),
    }
    for label, response in attempts.items():
        assert (response.status_code, _code(response)) == (403, "reauth_required"), (label, response.text[:200])
        assert response.headers["roxy-reauth"] == "required", label
    await api_app.ctx.settings.reload()
    assert int(api_app.ctx.settings.int(key)) == 1200  # nothing was written
    preview = await api.post("settings/preview", json={"changes": {key: 1500, "cache_ttl_seconds": 300}})
    assert preview.status_code == 200, preview.text[:200]  # a preview writes nothing: no factor needed
    assert (preview.json()["fresh_mfa_required"], preview.json()["fresh_mfa_keys"]) == (True, [key])
    ordinary = await api.put("settings/cache_ttl_seconds", json={"value": 300})
    assert ordinary.status_code == 200, ordinary.text[:200]  # ordinary settings do not ask for the factor
    unchanged = await api.patch("settings", json={"changes": {key: 1200}})
    assert unchanged.status_code == 200, unchanged.text[:200]  # the same value changes nothing: no factor needed
    await api.fresh_mfa()
    for label, response in {
        "PATCH": await api.patch("settings", json={"changes": {key: 1500}, "reason": "r"}),
        "revert": await api.post(f"settings/history/{history_id}/revert", json={"reason": "r"}),
        "reset": await api.post(f"settings/{key}/reset", json={"reason": "r"}),
    }.items():
        assert response.status_code == 200, (label, response.text[:200])


def test_the_fresh_factor_rule_covers_the_security_groups_and_raw_addresses() -> None:
    needs = {key for key, spec in catalog.CATALOG.items() if settings_api.needs_fresh_mfa(spec)}
    groups = {spec.group for spec in catalog.CATALOG.values() if spec.key in needs}
    # Outside the two security groups only the single settings of FRESH_MFA_SETTINGS (export_include_ips, and since
    # review round 4, finding secfix-6, health_auto_include_credential) need the factor.
    singles = {catalog.CATALOG[key].group for key in settings_api.FRESH_MFA_SETTINGS}
    assert groups <= set(settings_api.FRESH_MFA_GROUPS) | singles
    assert {"export_include_ips", "health_auto_include_credential"} == settings_api.FRESH_MFA_SETTINGS
    for key in (
        "admin_reauth_window_s",
        "admin_allowlist_enabled",
        "admin_session_max_age_s",
        "credential_probe_url",
        "credential_enabled",
        "admin_login_max_failures",
        "export_include_ips",
        "health_auto_include_credential",
    ):
        assert key in needs, key
    for key in ("cache_ttl_seconds", "spam_dry_run", "export_stable_ip_hash", "allowed_requests_per_minute"):
        assert key not in needs, key
    assert settings_api.fresh_mfa_keys(["cache_ttl_seconds", "admin_reauth_window_s", "no_such_key"]) == [
        "admin_reauth_window_s"
    ]
