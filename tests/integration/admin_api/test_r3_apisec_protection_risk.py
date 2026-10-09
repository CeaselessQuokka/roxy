"""Review round 3 (lens apisec): high-risk setting values through the Protection page's settings route.

What this is
    Strict-xfail test for finding apisec-4. DESIGN.md 13.1 makes `confirmation_required` (422) the one answer for
    a high-risk value without the explicit confirmation, "also in imports, reverts and recommendation applies", and
    the settings editor asks for `confirm_high_risk` plus a reason (`admin/api/settings.py check_risk`).
    `PATCH /admin/api/v1/protection/settings` writes the same catalog settings through the same settings service
    but never calls the risk check: a high-risk value is saved without the confirmation (the service itself only
    insists on a reason, and answers `invalid_settings` when it is missing, not `confirmation_required`).

Why it exists
    The Protection page holds the settings whose high-risk values hurt the most: `allowed_requests_per_minute` at
    1000 or more (the per-IP limit stops protecting Roblox), `bypass_default_expiry_h` at 0 (every new bypass entry
    is permanent), `ipv6_limit_prefix` above 64 (one IPv6 caller gets many limit keys), `throttle_strike_decay_seconds`
    at 0, `tarpit_max_capacity_fraction` above 0.4, `challenge_difficulty_bits` at 24 or more. The confirmation and
    the required reason (plan 15.2, 9.7) exist so these never change by a slip or without an audit reason.

How it works
    Control: the settings editor refuses the value (with a reason) when `confirm_high_risk` is missing. Then the
    Protection route is asked for the same value with the same reason and no confirmation; it should answer the
    same 422 and change nothing.

What to read next
    `roxy/admin/api/protection.py` (`settings_change`, `_check_protection_keys`), `roxy/admin/api/settings.py`
    (`check_risk`, `risk_reason`), `roxy/config/settings/throttling.py`.
"""

from __future__ import annotations

from typing import Any

import pytest

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


@pytest.mark.xfail(
    strict=True,
    reason="finding apisec-4: PATCH /protection/settings saves high-risk values without confirm_high_risk",
)
async def test_the_protection_route_asks_for_the_same_confirmation(api: Any, api_app: Any) -> None:
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
