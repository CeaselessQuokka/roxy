"""v1 parity: admin sign-in details the v2 auth tests did not pin end to end.

What this is
    Ports of v1 smoke lines 927 and 931 (S027: revoking trusted devices brings the second factor back) and line
    1570 (S053: after too many wrong passwords even the right one is refused with 429).

Why it exists
    The v2 auth tests prove the revoke route answers and the lockout counter counts; v1's suite also proved the
    consequence a person sees at the login form: a revoked device is asked for the second factor again, and a locked
    out address cannot get in with the correct password until the window passes.

How it works
    The `parity` fixture runs the real app with the real login flow (`roxy.admin.auth.testing.auth_harness`). The
    tests call the login steps directly (`password_step`), as the dashboard's login page does.

What to read next
    `roxy/admin/auth/flow.py` (the login transaction), `roxy/admin/auth/trusted_devices.py` and
    `roxy/admin/auth/lockout.py`.
"""

from __future__ import annotations

from typing import Any


async def test_v1_revoking_trusted_devices_brings_the_second_factor_back(parity: Any) -> None:
    """v1 smoke lines 927 and 931."""
    harness = parity.harness
    account = harness.admin(username="trusting")
    client = harness.new_client()
    assert (await harness.login(account, client=client, trust=True)).status_code == 200
    client.cookies.delete("__Host-roxy_session")
    skipped = await harness.password_step(account, client=client)
    assert skipped.json().get("LoggedIn") is True  # the trusted device skips the second factor
    revoked = await harness.post("/admin/api/v1/auth/trusted-devices/revoke-all", client=client)
    assert revoked.status_code == 200, revoked.text
    assert revoked.json()["Revoked"] >= 1
    client.cookies.delete("__Host-roxy_session")
    asked = await harness.password_step(account, client=client)
    assert asked.status_code == 200
    assert asked.json().get("TwoFA") is True  # asked for the second factor again


async def test_v1_brute_force_lockout_refuses_even_the_right_password(parity: Any) -> None:
    """v1 smoke line 1570: after the allowed number of wrong passwords from one address, the correct password gets
    429 with v1's "Too many attempts" text."""
    harness = parity.harness
    account = harness.admin(username="lockedout")
    limit = int(parity.ctx.settings.int("admin_login_max_failures"))
    for _ in range(limit):
        wrong = await harness.password_step(account, password="not the password at all", ip="192.0.2.200")
        assert wrong.status_code == 403
    locked = await harness.password_step(account, ip="192.0.2.200")
    assert locked.status_code == 429
    assert "Too many attempts" in locked.text
    assert "retry-after" in locked.headers
