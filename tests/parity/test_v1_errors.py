"""v1 parity: a real 500 is answered plainly, logged once per signature, and emailed once per cooldown.

What this is
    A port of v1 smoke sections S026 ("Error log (deduped, admin-clear only)", lines 893 to 895) and S054 ("Error
    emails still work for real 500s (rate-limited)", lines 1577 to 1582), with v1's test-only route that raises.

Why it exists
    v1 once mailed the owner for every bot probe; the fix kept mail for real crashes only, deduplicated and rate
    limited, and logged each crash signature with a count and its traceback. The v2 parts (the error middleware,
    the recorder's error table, the notifier's dedupe) have their own tests; this one proves them together.

How it works
    The `parity` fixture runs the real app with the notifier's mail recorded. A router with one GET route that
    raises `RuntimeError("intentional test explosion")` is added under `/admin` (the admin catch-all steps aside
    for routes added later). Two requests hit it; then the recorder is flushed, the System page's error table is
    read through the admin API and the recorded mail is counted.

What to read next
    `roxy/core/errors.py` (the 500 answer and the hooks), `roxy/metrics/recorder.py` (`record_error`) and
    `roxy/notify/notifier.py` (`error_alert`).
"""

from __future__ import annotations

from typing import Any

import httpx
from fastapi import APIRouter

BOOM = "/admin/_boom_test_only"


def boom_router() -> APIRouter:
    router = APIRouter()

    @router.get(BOOM)
    async def boom() -> None:
        raise RuntimeError("intentional test explosion")

    return router


def ok(response: httpx.Response) -> Any:
    assert response.status_code == 200, response.text
    return response.json()


async def test_v1_a_real_500_is_logged_with_its_traceback_and_mailed_once(parity: Any) -> None:
    """v1 smoke lines 893 to 895 and 1577 to 1582."""
    parity.app.include_router(boom_router())
    client = parity.harness.new_client()
    for _ in range(2):
        response = await client.get(BOOM, headers=parity.harness.headers())
        assert response.status_code == 500
        assert response.content == b'"Internal Server Error"\n'  # nothing about the exception leaks
    await parity.harness.drain()
    errors = [subject for subject in parity.mail.subjects() if subject.startswith("Roxy Error: RuntimeError")]
    assert len(errors) == 1  # the second crash within the cooldown sends nothing
    assert "Traceback" in parity.mail.bodies(errors[0])[0]

    parity.clock.advance(61)
    await parity.ctx.recorder.flush()
    admin = await parity.admin()
    rows = ok(await admin.get("system/errors"))["items"]
    crashes = [row for row in rows if "intentional test explosion" in row["signature"]]
    assert len(crashes) == 1  # one signature (v1's "Type: message"), deduplicated
    assert crashes[0]["signature"].startswith("RuntimeError")
    assert crashes[0]["count"] >= 2
    assert crashes[0]["has_traceback"] is True
