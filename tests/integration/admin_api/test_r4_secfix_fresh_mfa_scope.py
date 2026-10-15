"""Review round 4 (lens secfix): a setting that switches on what a fresh-factor action does needs the same factor.

What this is
    A test of the scope of the apisec-1 fix (`settings.needs_fresh_mfa`: the `admin_security` and `credential`
    groups, sensitive settings, and `FRESH_MFA_SETTINGS` = `export_include_ips`). The fixer added
    `export_include_ips` "which puts raw addresses in every download, as the LLM export's full detail does only
    with a fresh factor": a setting that turns on, for good, what an action guarded by the factor does once.
    `health_auto_include_credential` is the same case for the credential: a manual Check Proxy Health run that
    includes H-CRED-AUTH (one Roblox call with the credential, plan 13.3) needs a fresh second factor (DESIGN 14.4,
    `POST /health/runs`), and "scheduled runs include the credential checks only with health_auto_include_credential
    1". The setting sits in the `alerts` group, so a session whose factor went stale switches the scheduled
    credential calls on without the factor the manual run asks for.

Why it exists
    Plan 9.6 and DESIGN 14.4: use of the Roblox credential on an admin's initiative is a fresh-factor action; the
    standing switch for the same use must not be weaker than the one-off.

How it works
    The `api` fixture signs in; the clock is moved past `admin_reauth_window_s`. The manual credential health run is
    refused with 403 `reauth_required` (the control). Then the stale session turns
    `health_auto_include_credential` on through `PUT /settings/{key}`; it must be refused the same way. This was a
    strict xfail (finding secfix-6); the setting is now in `FRESH_MFA_SETTINGS`.

What to read next
    `roxy/admin/api/settings.py` (`needs_fresh_mfa`, `FRESH_MFA_SETTINGS`), `roxy/admin/api/health.py` (the manual
    run's guard), `roxy/health/runner.py` (`scheduled_run`, `health_auto_include_credential`).
"""

from __future__ import annotations

from typing import Any


def _code(response: Any) -> str | None:
    try:
        body = response.json()
    except ValueError:
        return None
    error = body.get("error") if isinstance(body, dict) else None
    return error.get("code") if isinstance(error, dict) else None


async def test_scheduled_credential_checks_need_the_factor_a_manual_one_needs(api: Any, api_app: Any) -> None:
    await api_app.settings(health_auto_interval_h=0)  # no scheduled run starts during the test
    api.make_mfa_stale()
    manual = await api.post("health/runs", json={"include_credential": True})
    assert (manual.status_code, _code(manual)) == (403, "reauth_required"), manual.text[:200]  # the control
    standing = await api.put(
        "settings/health_auto_include_credential", json={"value": 1, "reason": "r", "confirm_high_risk": True}
    )
    assert (standing.status_code, _code(standing)) == (403, "reauth_required"), (
        f"the stale session switched scheduled credential checks on: {standing.status_code} {standing.text[:160]}"
    )
