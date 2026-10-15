"""Review round 3 (lens apisec): high-risk setting values through the Protection page's settings route.

What this is
    Tests for finding apisec-4 (fixed; it was a strict xfail). DESIGN.md 13.1 makes `confirmation_required` (422)
    the one answer for
    a high-risk value without the explicit confirmation, "also in imports, reverts and recommendation applies", and
    the settings editor asks for `confirm_high_risk` plus a reason (`admin/api/settings.py check_risk`).
    `PATCH /admin/api/v1/protection/settings` writes the same catalog settings through the same settings service
    and used to skip the risk check, so a high-risk value was saved without the confirmation (the service itself
    only insists on a reason). It now runs the editor's rules (`protection.check_settings_change`).

Why it exists
    The Protection page holds the settings whose high-risk values hurt the most: `allowed_requests_per_minute` at
    1000 or more (the per-IP limit stops protecting Roblox), `bypass_default_expiry_h` at 0 (every new bypass entry
    is permanent), `ipv6_limit_prefix` above 64 (one IPv6 caller gets many limit keys), `throttle_strike_decay_seconds`
    at 0, `tarpit_max_capacity_fraction` above 0.4, `challenge_difficulty_bits` at 24 or more. The confirmation and
    the required reason (plan 15.2, 9.7) exist so these never change by a slip or without an audit reason.

How it works
    Control: the settings editor refuses the value (with a reason) when `confirm_high_risk` is missing. Then the
    Protection route is asked for the same value with the same reason and no confirmation; it answers the same 422
    and changes nothing. With the confirmation and a reason the value is saved; low-risk values need neither.

What to read next
    `roxy/admin/api/protection.py` (`settings_change`, `_check_protection_keys`), `roxy/admin/api/settings.py`
    (`check_risk`, `risk_reason`), `roxy/config/settings/throttling.py`.
"""

from __future__ import annotations

from typing import Any

RISKY: dict[str, Any] = {"allowed_requests_per_minute": 5000, "bypass_default_expiry_h": 0}
"""Two Protection settings at a value their catalog entry marks high risk."""


def _code(response: Any) -> str | None:
    body = response.json()
    error = body.get("error") if isinstance(body, dict) else None
    return error.get("code") if isinstance(error, dict) else None


async def test_the_settings_editor_asks_for_the_confirmation(api: Any) -> None:
    """Control (passes today)."""
    for key, value in RISKY.items():
        response = await api.patch("settings", json={"changes": {key: value}, "reason": "load test"})
        assert response.status_code == 422, (key, response.text[:200])
        assert _code(response) == "confirmation_required", key


async def test_the_protection_route_asks_for_the_same_confirmation(api: Any, api_app: Any) -> None:
    """Finding apisec-4 (fixed): the Protection route runs the editor's risk rule before the settings service."""
    before = {key: api_app.ctx.settings.get(key) for key in RISKY}
    saved: list[str] = []
    for key, value in RISKY.items():
        response = await api.patch("protection/settings", json={"changes": {key: value}, "reason": "load test"})
        if response.status_code != 422 or _code(response) != "confirmation_required":
            saved.append(f"{key}={value}: {response.status_code}")
    await api_app.ctx.settings.reload()
    after = {key: api_app.ctx.settings.get(key) for key in RISKY}
    assert saved == [], "high-risk values accepted without confirmation: " + "; ".join(saved)
    assert after == before


async def test_a_confirmed_high_risk_value_still_needs_a_reason_and_then_saves(api: Any, api_app: Any) -> None:
    """With `confirm_high_risk` the value is saved, but only with a reason (the editor's rule, plan 15.2, 9.7); a
    batch that mixes a risky value with a plain one is refused whole, so nothing half applies."""
    key, value = "allowed_requests_per_minute", 5000
    mixed = {key: value, "flood_limit_per_minute": 900}
    refused = await api.patch("protection/settings", json={"changes": mixed, "reason": "load test"})
    assert refused.status_code == 422, refused.text[:200]
    assert _code(refused) == "confirmation_required", refused.text[:200]
    no_reason = await api.patch("protection/settings", json={"changes": {key: value}, "confirm_high_risk": True})
    assert no_reason.status_code == 422, no_reason.text[:200]
    await api_app.ctx.settings.reload()
    assert api_app.ctx.settings.get("flood_limit_per_minute") != 900
    assert api_app.ctx.settings.get(key) != value
    saved = await api.patch(
        "protection/settings", json={"changes": {key: value}, "reason": "load test", "confirm_high_risk": True}
    )
    assert saved.status_code == 200, saved.text[:200]
    await api_app.ctx.settings.reload()
    assert api_app.ctx.settings.get(key) == value


async def test_a_low_risk_change_needs_no_confirmation(api: Any, api_app: Any) -> None:
    """The rule asks only for high-risk values: an ordinary limit change saves as before (no new friction)."""
    response = await api.patch("protection/settings", json={"changes": {"allowed_requests_per_minute": 120}})
    assert response.status_code == 200, response.text[:200]
    await api_app.ctx.settings.reload()
    assert api_app.ctx.settings.get("allowed_requests_per_minute") == 120
