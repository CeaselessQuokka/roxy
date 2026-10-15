"""P11 review, lens authz (authentication, authorization, CSRF, CSP and headers): server side reproductions.

What this is
    Reproductions of the authz lens findings against the real app in process (the fixtures of
    `tests/integration/pages/conftest.py`: `pages_app`, `page`). Each was a strict xfail naming its finding
    id until the finding was fixed in the P11 review round; each is a regression test now. The report is
    `.remake/p11_review/find_authz.md`. The refuted authz-3 (a signed-out fragment answers 302 to the login, the
    recorded contract of P11_CONTRACT section 4 and DESIGN 11.9) has no test here.

Why it exists
    A finding without a reproduction is not a finding: each test failed for the stated reason and passes since the
    fix, without weakening any existing assertion.

What to read next
    `tests/review_p11/test_authz_e2e.py` (the browser side), `src/roxy/admin/auth/deps.py`,
    `src/roxy/admin/auth/allowlist.py`, `src/roxy/admin/api/settings.py`.
"""

# ruff: noqa: F811  (the imported pytest fixtures are the tests' parameters)
from __future__ import annotations

from typing import Any

import pytest

from integration.pages.conftest import page, page_admin, pages_app  # noqa: F401  (the page fixtures)

ADMIN_ACCESS_PAGE = "/admin/security"


# ------------------------------------------------------------------------------------------------ authz-2


# Fixed in the P11 review round (authz-2, shared fixer): a regression test now.
async def test_authz_2_switching_the_allowlist_on_never_locks_the_admin_out_unasked(page: Any) -> None:
    card = await page.fragment("security", "admin-access")  # a lazy card: its fragment holds the inline switch
    assert card.status_code == 200
    assert 'data-setting-key="admin_allowlist_enabled"' in card.text  # the page offers the switch
    await page.fresh_mfa()  # the admin_security group needs a fresh second factor; the admin has one
    # Exactly what the inline control sends after Review (static/js/settings_api.js): no lockout confirmation.
    answer = await page.api(
        "PUT", "settings/admin_allowlist_enabled", json={"value": "1", "reason": "Hide the dashboard"}
    )
    after = await page.get(ADMIN_ACCESS_PAGE)
    assert after.status_code == 200, (
        f"the PUT answered {answer.status_code} and the admin's own dashboard now answers {after.status_code}: "
        "the allowlist was switched on with no entry covering the admin's address (127.0.0.1), and nothing asked "
        "for the confirm_lockout that removing such an entry needs"
    )


# Fixed in the P11 review round (authz-2, shared fixer): a regression test now.
async def test_authz_2_a_settings_batch_never_locks_the_admin_out_unasked(page: Any, pages_app: Any) -> None:
    await pages_app.harness.allow_admin_cidr("198.51.100.0/24")  # an entry exists, but not for the admin's network
    await page.fresh_mfa()
    answer = await page.api(
        "PATCH", "settings", json={"changes": {"admin_allowlist_enabled": 1}, "reason": "Hide the dashboard"}
    )
    after = await page.get("/admin/settings")
    assert after.status_code == 200, (
        f"the batch answered {answer.status_code}; the Settings page now answers {after.status_code} to its admin"
    )


async def _allowlist_recommendation(pages_app: Any, network: str) -> Any:
    """An open SEC-ADMIN-ALLOWLIST recommendation that adds `network` to the admin allowlist, then switches it on
    (the rule's own order: entries first, the switch last), written with the engine's writer."""
    from roxy.config.insight_params import INSIGHT_RULES
    from roxy.core.ids import new_id
    from roxy.insights.engine import write_recommendation
    from roxy.insights.models import Evidence, ProposedChange, Recommendation, make_fingerprint

    now = pages_app.clock.now()
    rule_id = "SEC-ADMIN-ALLOWLIST"
    row = {"kind": "allow_admin", "cidr": network, "note": "SEC-ADMIN-ALLOWLIST: admin logins seen here"}
    rec = Recommendation(
        rule_id=rule_id,
        family=INSIGHT_RULES[rule_id].family,
        subject=f"admin logins from {network}",
        title="Hide the dashboard from other networks",
        severity="info",
        confidence="low",
        explanation="Every admin login came from one network.",
        evidence=Evidence(window_from=now - 86_400, window_to=now, sample_size=3).add("successful_logins", 3, "logins"),
        changes=[
            ProposedChange(
                "rule_upsert",
                table="access_list",
                match={"kind": "allow_admin", "cidr": network},
                proposed={**row, "expires_at": None},
            ),
            ProposedChange("setting", key="admin_allowlist_enabled", current=0, proposed=1),
        ],
        expected_impact="Only that network sees /admin.",
        risk="medium",
    )
    rec.id = new_id("rec", pages_app.clock)
    rec.fingerprint = make_fingerprint(rule_id, rec.subject)
    rec.computed_severity = rec.severity
    rec.state = "open"
    rec.created_at = rec.updated_at = now
    rec.expires_at = now + 7 * 86_400
    await pages_app.ctx.dbs.metrics.write(lambda conn: write_recommendation(conn, rec))
    return rec


# Found by the gate of the P11 review round: the fifth path the authz-2 finding names (SEC-ADMIN-ALLOWLIST applied
# from a network its evidence did not see) is held to the same lockout rule (recommendations.lockout_check).
async def test_authz_2_a_recommendation_never_switches_the_allowlist_on_for_an_admin_it_does_not_cover(
    page: Any, pages_app: Any
) -> None:
    from roxy.insights.models import changes_digest

    elsewhere = await _allowlist_recommendation(pages_app, "198.51.100.0/24")  # not the admin's 127.0.0.1
    await page.fresh_mfa()  # the change touches the admin allowlist: a fresh second factor is asked first
    body = {"changes_digest": changes_digest(elsewhere.changes), "reason": "Hide the dashboard"}
    refused = await page.api("POST", f"recommendations/{elsewhere.id}/apply", json=body)
    assert refused.status_code == 422, refused.text
    error = refused.json()["error"]
    assert error["code"] == "confirmation_required"
    assert "admin_allowlist_enabled" in error["fields"]
    assert (await page.get("/admin/recommendations")).status_code == 200  # still signed in, nothing applied
    assert not pages_app.ctx.settings.bool("admin_allowlist_enabled")
    # A recommendation whose entries cover the admin's own network applies, and the admin keeps the dashboard.
    mine = await _allowlist_recommendation(pages_app, "127.0.0.0/24")
    body = {"changes_digest": changes_digest(mine.changes), "reason": "Hide the dashboard"}
    applied = await page.api("POST", f"recommendations/{mine.id}/apply", json=body)
    assert applied.status_code == 200, applied.text
    assert (await page.get("/admin/recommendations")).status_code == 200


# ------------------------------------------------------------------------------------------------ authz-4


# Fixed in the P11 review round (authz-4, shared fixer): a regression test now.
async def test_authz_4_a_session_check_that_cannot_read_control_db_never_signs_the_page_out(
    page: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    from integration.admin_api.test_sse import open_stream  # the ASGI stream driver of the stream's own tests
    from roxy.admin import sse
    from roxy.admin.auth import flow

    monkeypatch.setattr(sse, "SESSION_CHECK_S", 0.1)
    stream = await open_stream(page, {"events": "kpi,settings_changed"})
    assert stream.status == 200
    try:

        async def unreadable(self: Any, token: str | None) -> Any:
            raise flow.unavailable()  # what `control_read` raises while shared state cannot be read (plan C7)

        monkeypatch.setattr(flow.AuthService, "load_session", unreadable)
        frames = await stream.drain(1.5)  # fifteen session checks; SESSION_FAILURES_MAX is 3
    finally:
        await stream.close()
    signed_out = [frame for frame in frames if frame.event == "unauthorized"]
    assert not signed_out, (
        "the stream told the page its session ended (static/js/sse.js then stops for good and shows the "
        "session-expired overlay) only because control.db could not be read; sse.SESSION_FAILURES_MAX says the "
        "reconnect should decide (it would get 503 and retry)"
    )
