"""The Health page in a real browser (P11): clean, accessible, and a health check runs from a phone.

What this is
    Browser tests against the real app (`dashboard`, tests/e2e/conftest.py). For each theme and size (1440x900 and
    390x844, dark and light) the page loads with no console error, page error or CSP violation, axe-core finds nothing
    serious, the phone layout never scrolls sideways, and a screenshot is saved for the visual review. Then the flows
    of plan 13.1 and 14.8: on a phone, run a check without the credential check and watch the Run card follow it
    until it finishes (the live view over the event stream, with the page's own poll as the fallback); with the
    credential check and an old second factor, "Confirm it is you" comes first and the run starts after the code;
    a run already going is followed instead of failing; two runs compare; "Copy for LLM" puts the run on the clipboard.
    Every run started here is real (the runner, the checks, the store) inside the harness's loopback guard: a check
    that would leave the machine is refused at once and reported as a failure, nothing reaches any real host.

Why it exists
    Only a browser proves the live run view, the SSE stream, the reauth prompt and the strict CSP work together.

What to read next
    tests/e2e/conftest.py, tests/integration/pages/test_page_health.py, static/js/pages/health.js.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest

from roxy.admin.pages.testing import SESSION_COOKIE_NAME, THEMES, VIEWPORTS
from roxy.health import store
from roxy.health.model import CheckResult, Status
from roxy.health.runner import RUN_LEASE, RUN_LEASE_TTL_MS
from roxy.storage import leases

PAGE = "/admin/health"
NO_HOSTILE_MARKUP = """() => !document.querySelector('img[src="x"], [onerror], [onclick], a[href^="javascript:"]')
  && typeof window.__pwned === "undefined\""""
FINISHED = "document.querySelector('#run [data-run-id=\"{run}\"][data-run-state=\"finished\"]') !== null"
RUN_TIMEOUT_S = 150


@pytest.fixture(autouse=True)
def no_scheduled_runs(dashboard: Any) -> Iterator[None]:
    """Scheduled runs off while these tests run (one run at a time in the fleet: a scheduled one would take it)."""
    dashboard.change_settings({"health_auto_interval_h": 0})
    yield


def newest_run(dashboard: Any) -> int:
    return int(dashboard.api("GET", "health/runs/latest").json()["id"])


def keep_cookie(page: Any, dashboard: Any) -> None:
    """A fresh second factor rotates the session: hand the browser's new cookie back to the fixture."""
    for cookie in page.context.cookies():
        if cookie["name"] == SESSION_COOKIE_NAME:
            dashboard.signed_in.cookie = cookie["value"]


@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("size", list(VIEWPORTS))
def test_the_page_is_clean_accessible_and_fits(open_admin: Any, theme: str, size: str) -> None:
    width, height = VIEWPORTS[size]
    admin = open_admin(PAGE, theme=theme, width=width, height=height)
    page = admin.page
    assert page.locator('#run [data-action="health-run"]').count() == 1
    assert page.locator("#run [data-check]").count() >= 1
    assert page.locator('#history [data-table="health_runs"] tbody tr[data-row-id]').count() >= 1
    assert page.evaluate(NO_HOSTILE_MARKUP)
    assert not admin.overflows(), "the page scrolls sideways"
    assert admin.axe() == []
    admin.shot("health")
    admin.assert_clean()


def test_a_run_from_a_phone_fills_in_live_and_finishes(open_admin: Any, dashboard: Any) -> None:
    admin = open_admin(PAGE, width=390, height=844)
    page = admin.page
    before = newest_run(dashboard)
    page.locator('#run input[name="include_credential"]').uncheck()
    page.locator('#run [data-action="health-run"]').click()
    admin.wait(f"(() => {{ const n = document.querySelector('#run [data-run-id]'); return n && Number(n.dataset.runId) > {before}; }})()")
    run_id = int(page.locator("#run [data-run-id]").first.get_attribute("data-run-id") or 0)
    assert f"run={run_id}" in page.url
    admin.wait(FINISHED.format(run=run_id), timeout=RUN_TIMEOUT_S)
    assert page.locator("#run [data-check]").count() > 20
    assert page.locator('#run [data-check-status="pending"]').count() == 0
    assert page.locator('#run [data-check="H-CRED-AUTH"]').get_attribute("data-check-status") == "n/a"
    admin.wait(f"document.querySelector('#history tr[data-row-id=\"run-{run_id}\"]') !== null")
    assert not admin.overflows()
    assert admin.axe() == []
    admin.shot("health-run")
    admin.assert_clean()


def test_the_credential_check_asks_for_the_second_factor_first(open_admin: Any, dashboard: Any) -> None:
    window = dashboard.api("GET", "settings/admin_reauth_window_s").json()["setting"]["value"]
    dashboard.clock.advance(int(window) + 1)  # the session lives on (idle timeout 900 s); its factor is old
    admin = open_admin(PAGE, width=390, height=844)
    page = admin.page
    before = newest_run(dashboard)
    try:
        assert page.locator('#run input[name="include_credential"]').is_checked()
        page.locator('#run [data-action="health-run"]').click()
        admin.wait("document.querySelector('#reauth[open]') !== null")
        assert admin.axe() == []
        page.fill("#reauth-code", dashboard.next_code())
        page.locator('#reauth button[type="submit"]').click()
        admin.wait(f"(() => {{ const n = document.querySelector('#run [data-run-id]'); return n && Number(n.dataset.runId) > {before}; }})()")
        run_id = int(page.locator("#run [data-run-id]").first.get_attribute("data-run-id") or 0)
        admin.wait(FINISHED.format(run=run_id), timeout=RUN_TIMEOUT_S)
        assert page.locator('#run [data-check="H-CRED-AUTH"]').get_attribute("data-check-status") != "n/a"
    finally:
        keep_cookie(page, dashboard)
    admin.assert_clean(expected=["status of 403"])


def test_a_run_going_in_another_worker_is_followed_live(open_admin: Any, dashboard: Any) -> None:
    """Another worker holds the fleet's one-run lease: Run answers 409 with that run's id, the card follows it, and
    the results that worker writes arrive over the event stream until the run finishes."""
    holder = "another-worker#e2e"
    ctx = dashboard.ctx
    disk = CheckResult("H-DISK", Status.PASS, "40% free", "25%", "Free disk space is fine.", "")
    config = CheckResult("H-CONFIG", Status.WARN, "1 warning", "0", "One stored key is unknown.", "/admin/settings")

    async def begin() -> int:
        now_ms = int(ctx.clock.now_ms())
        await ctx.dbs.hot.write(lambda conn: leases.acquire(conn, RUN_LEASE, holder, RUN_LEASE_TTL_MS, now_ms))
        options = {"checks": ["H-DISK", "H-CONFIG"], "include_credential": False}
        run: int = await ctx.dbs.metrics.write(
            lambda conn: store.insert_run(
                conn, started_at=now_ms // 1000, trigger="cli", version="test", options=options, actor="cli:e2e",
                at_ms=now_ms, planned=2,
            )
        )  # fmt: skip
        return run

    async def report(run: int, result: CheckResult, *, finish: bool = False) -> None:
        now_ms = int(ctx.clock.now_ms())

        def write(conn: Any) -> None:
            store.insert_result(conn, run, result, at_ms=now_ms)
            if finish:
                summary = store.summarize([disk, config])
                store.finish_run(conn, run, finished_at=now_ms // 1000, summary=summary, at_ms=now_ms, trigger="cli")

        await ctx.dbs.metrics.write(write)

    async def end() -> None:
        await ctx.dbs.hot.write(lambda conn: leases.release(conn, RUN_LEASE, holder, delete=True))

    run_id = dashboard.run(begin())
    try:
        admin = open_admin(PAGE)
        page = admin.page
        page.locator('#run input[name="include_credential"]').uncheck()
        page.locator('#run [data-action="health-run"]').click()
        admin.wait(f"document.querySelector('#run [data-run-id=\"{run_id}\"][data-run-state=\"running\"]') !== null")
        admin.wait("/already running/.test(document.querySelector('#toasts').innerText)")
        assert page.locator('#run [data-check-status="pending"]').count() == 2
        dashboard.run(report(run_id, disk))
        admin.wait("document.querySelector('#run [data-check=\"H-DISK\"][data-check-status=\"pass\"]') !== null")
        assert "1 of 2 checks done" in page.locator("#run .hl-progress").inner_text()
        dashboard.run(report(run_id, config, finish=True))
        admin.wait(FINISHED.format(run=run_id), timeout=20)
        admin.wait(f"/Health run {run_id} finished/.test(document.querySelector('#toasts').innerText)")
    finally:
        dashboard.run(end())
    admin.assert_clean(expected=["status of 409"])


def test_two_runs_compare_and_copy_for_llm(open_admin: Any, dashboard: Any) -> None:
    latest = newest_run(dashboard)
    runs = dashboard.api("GET", "health/runs", params={"page_size": 10}).json()["items"]
    earlier = next(item["id"] for item in runs if item["id"] != latest and item["state"] == "finished")
    admin = open_admin(f"{PAGE}?run={latest}")
    page = admin.page
    context = page.context
    context.grant_permissions(["clipboard-read", "clipboard-write"], origin=admin.base_url)
    page.select_option('#run select[name="with"]', str(earlier))
    page.locator('#run [data-action="health-compare"]').click()
    page.wait_for_url(f"**with={earlier}*")
    admin.settle()
    assert page.locator(f'#run [data-compare-with="{earlier}"] tbody tr').count() > 0
    page.locator('#run [data-action="health-copy-llm"]').click()
    admin.wait("/Copied/.test(document.querySelector('#toasts').innerText)")
    copied = page.evaluate("navigator.clipboard.readText()")
    assert "untrusted" in copied
    assert f'"id": {latest}' in copied or str(latest) in copied
    admin.assert_clean()
