"""Review round 4 (lens secfix): a lagging settings snapshot never decides the fresh-factor and arming rules.

What this is
    Adversarial tests of the apisec-1 fix (and of the `spam_dry_run` arming rule it sits next to). Every settings
    writer of the admin API (`PATCH /settings`, `PUT /settings/{key}`, `POST /settings/{key}/reset`, the Protection
    routes) works out which keys a request "would change" from this worker's settings SNAPSHOT
    (`ctx.settings.snapshot()`, `settings.preview_changes`, `changing_keys`, `is_overridden`), and asks for a fresh
    second factor (or refuses to arm the spam detectors) only for those keys. The write itself
    (`SettingsService._apply`) compares the request with control.db inside its transaction and writes every key
    whose stored value differs. A snapshot is up to `CONFIG_POLL_INTERVAL_S` (1 s) behind a change another worker
    (or another admin) made, so in that window a request that "changes nothing" by the snapshot writes a sensitive
    key back without any fresh factor.

Why it exists
    Plan 9.6 and finding apisec-1: a session whose second factor went stale must not change an `admin_security` or
    `credential` setting. The realistic attack: the owner reacts to a stolen session by switching the admin
    allowlist on (or the credential off) in one tab; the attacker's script keeps sending "switch it off" to every
    worker; each request lands on a worker whose snapshot still holds the old value, passes the guard, and the
    write reverts the owner's change. With 2 to 4 workers (C6) one of them is always behind for a moment.

How it works
    The `api` fixture signs in; the clock is moved past `admin_reauth_window_s` (a stale factor, checked against a
    fresh-factor route). The config watcher's refresh of this worker is frozen (`refresh_if_changed` replaced by a
    no-op, standing for the up-to-1 s lag), then "another worker" writes the owner's change through its own
    `SettingsService` (no runtime attached, so this worker's snapshot does not move). The stale session then asks
    this worker to put the old value back. These were strict xfails (finding secfix-1); since the fix every writer
    passes `settings.write_rules` as the service's guard, which judges the fresh factor, arming and the high-risk
    confirmation on the keys the control.db transaction is about to write, so each attempt is refused and control.db
    keeps the owner's value.

What to read next
    `roxy/admin/api/settings.py` (`WriteRules`, `write_rules`, `update_settings`, `set_setting`, `reset_setting`),
    `roxy/config/settings_service.py` (`PendingWrite`, `WriteGuard`, `_apply`), `roxy/config/runtime.py`.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from roxy.config import catalog
from roxy.config.audit import Actor
from roxy.config.settings_service import SettingsService

REGENERATE = "security/recovery-codes/regenerate"


def _code(response: Any) -> str | None:
    try:
        body = response.json()
    except ValueError:
        return None
    error = body.get("error") if isinstance(body, dict) else None
    return error.get("code") if isinstance(error, dict) else None


async def _stored(api_app: Any, key: str) -> Any:
    """The value control.db holds for `key` now (its override, else the catalog default)."""

    def read(conn: Any) -> Any:
        row = conn.execute("SELECT value_json FROM settings WHERE key = ?", (key,)).fetchone()
        return catalog.DEFAULTS.get(key, catalog.CATALOG[key].default) if row is None else json.loads(row[0])

    return await api_app.ctx.dbs.control.read(read)


async def _freeze_this_worker(api_app: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """This worker's watcher misses the next change for a moment (what `CONFIG_POLL_INTERVAL_S` allows)."""

    async def unchanged() -> bool:
        return False

    monkeypatch.setattr(api_app.ctx.settings, "refresh_if_changed", unchanged)


async def _other_worker_writes(api_app: Any, **values: Any) -> None:
    """The owner's change, made through another worker (its own service, this worker's snapshot untouched)."""
    other = SettingsService(api_app.ctx.dbs.control, runtime=None, clock=api_app.clock)
    result = await other.update(values, Actor("admin", "owner"), "owner reacts to a stolen session")
    assert result.changes, values


async def _stale(api: Any) -> None:
    api.make_mfa_stale()
    refused = await api.post(REGENERATE, json={})
    assert (refused.status_code, _code(refused)) == (403, "reauth_required"), refused.text[:200]


async def test_a_stale_session_cannot_switch_the_allowlist_off_through_a_lagging_worker(
    api: Any, api_app: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    await _stale(api)
    await _freeze_this_worker(api_app, monkeypatch)
    await _other_worker_writes(api_app, admin_allowlist_enabled=1)
    assert int(api_app.ctx.settings.int("admin_allowlist_enabled")) == 0  # this worker has not seen it yet
    attempt = await api.put(
        "settings/admin_allowlist_enabled", json={"value": 0, "reason": "off", "confirm_high_risk": True}
    )
    stored = await _stored(api_app, "admin_allowlist_enabled")
    assert (attempt.status_code, _code(attempt), stored) == (403, "reauth_required", 1), (
        f"stale session answered {attempt.status_code}; control.db now holds admin_allowlist_enabled={stored!r}"
    )


async def test_a_stale_session_cannot_switch_the_credential_back_on_through_a_lagging_worker(
    api: Any, api_app: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    await _stale(api)
    await _freeze_this_worker(api_app, monkeypatch)
    await _other_worker_writes(api_app, credential_enabled=0)
    attempt = await api.patch(
        "settings", json={"changes": {"credential_enabled": 1}, "reason": "on", "confirm_high_risk": True}
    )
    stored = await _stored(api_app, "credential_enabled")
    assert (attempt.status_code, _code(attempt)) == (403, "reauth_required"), (
        f"stale session answered {attempt.status_code}; control.db now holds credential_enabled={stored!r}"
    )
    assert stored == 0


async def test_a_stale_session_cannot_reset_a_fresh_override_through_a_lagging_worker(
    api: Any, api_app: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    await _stale(api)
    await _freeze_this_worker(api_app, monkeypatch)
    await _other_worker_writes(api_app, admin_reauth_window_s=120)  # the owner shortens the window
    attempt = await api.post("settings/admin_reauth_window_s/reset", json={"reason": "default"})
    stored = await _stored(api_app, "admin_reauth_window_s")
    assert (attempt.status_code, _code(attempt), stored) == (403, "reauth_required", 120), (
        f"stale session answered {attempt.status_code}; control.db now holds admin_reauth_window_s={stored!r}"
    )


async def test_the_settings_editor_never_arms_the_spam_detectors_through_a_lagging_worker(
    api: Any, api_app: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    await api_app.settings(spam_dry_run=0)  # armed once, the proper way (the test's own setup)
    await _freeze_this_worker(api_app, monkeypatch)
    await _other_worker_writes(api_app, spam_dry_run=1)  # the owner disarms them in another tab
    attempt = await api.patch("settings", json={"changes": {"spam_dry_run": 0}, "reason": "arm"})
    stored = await _stored(api_app, "spam_dry_run")
    assert (attempt.status_code, _code(attempt), stored) == (422, "confirmation_required", 1), (
        f"PATCH spam_dry_run=0 answered {attempt.status_code}; control.db now holds spam_dry_run={stored!r} "
        "(armed without POST /protection/spam/arm)"
    )
