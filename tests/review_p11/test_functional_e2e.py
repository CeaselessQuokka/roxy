"""P11 review, functional lens: reproductions in a real browser (the dashboard's own scripts).

What this is
    Each test reproduces one finding of `.remake/p11_review/find_functional.md` that only a browser shows: two
    admins at once, the event stream dropping and coming back, the top bar and banners after a change, a reload
    the admin refuses, and the editor and the bell after an action. The fixtures are those of `tests/e2e/conftest.py`
    (`dashboard`: the real app on a free loopback port with a signed-in admin and seeded data; `open_admin`: a page
    in its own browser context), imported here as the e2e tests get them from their conftest.

Why it exists
    The review rule: a finding without a reproduction is not a finding. Every test was
    `@pytest.mark.xfail(strict=True)` until its finding was fixed; each is now a regression test (a comment above it
    names the fix). A test that changes shared state (a setting, the pause, the emergency limit) puts it back in a
    `finally`.

How it works
    "The other admin" is `dashboard.api(...)`: the same admin API a second browser would call. A test waits for the
    page-wide stream to deliver the change (`roxy:sse:settings_changed`) before it acts, so it never races the
    stream; waits tolerate the page reloading itself.

What to read next
    `tests/review_p11/test_functional.py` (the integration half), `static/js/settings_api.js`,
    `static/js/shell.js`, `static/js/sse.js`, `roxy/admin/sse.py`.
"""

# ruff: noqa: F811  (the imported pytest fixtures are the tests' parameters)

from __future__ import annotations

import time
from typing import Any

from e2e.conftest import browser, dashboard, open_admin  # noqa: F401  (the browser fixtures)

COUNT_CHANGES = (
    "window.__changes = 0; document.addEventListener('roxy:sse:settings_changed', () => { window.__changes += 1; });"
)


def value_of(dashboard: Any, key: str) -> Any:
    return dashboard.api("GET", f"settings/{key}").json()["setting"]["value"]


def eventually(page: Any, expression: str, timeout_s: float) -> bool:
    """True once `expression` is truthy in the page (a reload on the way is fine), False at the deadline."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            if page.evaluate(expression):
                return True
        except Exception:  # the page is navigating: try again on the new document
            pass
        page.wait_for_timeout(200)
    return False


# ============================================================================================ functional-3


# Fixed in the P11 review round (functional-3, shared fixer): a regression test now.
def test_a_value_another_admin_saved_is_not_overwritten_from_a_stale_review(open_admin: Any, dashboard: Any) -> None:
    key = "cache_ttl_seconds"
    before = int(value_of(dashboard, key))
    mine, theirs = before + 11, before + 50
    try:
        admin = open_admin("/admin/cache")
        page = admin.page
        page.evaluate(COUNT_CHANGES)
        form = page.locator(f'form[data-setting-key="{key}"]').first
        form.locator("[data-setting-input]").fill(str(mine))
        form.locator('button[type="submit"]').click()  # Review: "Now <before>, After saving <mine>"
        admin.wait(f"!document.querySelector('form[data-setting-key=\"{key}\"] [data-setting-review]').hidden")
        answer = dashboard.api("PUT", f"settings/{key}", json={"value": str(theirs), "reason": "the other admin"})
        assert answer.status_code == 200, answer.text
        assert eventually(page, "window.__changes >= 1", 15), "the stream reported the other admin's change"
        page.wait_for_timeout(1000)
        # What the first admin does next: press the control's button again (it still says Save).
        page.locator(f'form[data-setting-key="{key}"] button[type="submit"]').first.click()
        page.wait_for_timeout(2500)
        assert int(value_of(dashboard, key)) == theirs, (
            f"the other admin's {theirs} was replaced by {mine} without a word (the review still said Now {before})"
        )
    finally:
        dashboard.change_settings({key: before})


# ============================================================================================ functional-5


# Fixed in the P11 review round (functional-5, shared fixer): a regression test now.
def test_a_change_made_while_the_stream_was_down_reaches_the_page(open_admin: Any, dashboard: Any) -> None:
    calls = {"stream": 0}

    def first_stream_drops(route: Any) -> None:
        calls["stream"] += 1
        if calls["stream"] == 1:
            # While this page has no stream, another admin pauses the proxy; then the connection ends.
            seen = int(dashboard.ctx.settings.version)
            answer = dashboard.api("POST", "protection/pause", json={"paused": True})
            assert answer.status_code == 200, answer.text
            # The worker's settings snapshot takes the new config_version within a second (`watch_config`). A drop
            # longer than that (a deploy, a laptop waking up) reconnects after it did; without this wait the
            # reconnect can win the race, start at the old version and report the change by luck (skeptic fix:
            # the test passed one run in two).
            deadline = time.monotonic() + 5
            while int(dashboard.ctx.settings.version) == seen and time.monotonic() < deadline:
                time.sleep(0.05)
            route.fulfill(status=200, headers={"Content-Type": "text/event-stream"}, body="retry: 1000\n\n")
        else:
            route.continue_()

    try:
        admin = open_admin(None)
        admin.page.route("**/admin/api/v1/stream**", first_stream_drops)
        admin.goto("/admin/overview")
        page = admin.page
        assert eventually(page, "document.querySelector('[data-live-indicator]').dataset.state === 'live'", 15)
        assert calls["stream"] >= 2, "the stream reconnected"
        shows_paused = eventually(page, "document.querySelector('.topbar__pause').textContent.includes('Resume')", 15)
        assert shows_paused, "the top bar still offers Pause (and no banner) while the proxy refuses every request"
    finally:
        dashboard.api("POST", "protection/pause", json={"paused": False})


# ============================================================================================ functional-6


# Fixed in the P11 review round (functional-6, shared fixer): a regression test now.
def test_the_emergency_limit_banner_follows_a_new_limit(open_admin: Any, dashboard: Any) -> None:
    keys = ("global_throttle_limit", "global_throttle_period")
    before = {key: value_of(dashboard, key) for key in keys}
    try:
        answer = dashboard.api("POST", "protection/throttle-all", json={"enabled": True, "limit": 5, "period": 60})
        assert answer.status_code == 200, answer.text
        admin = open_admin("/admin/overview")
        page = admin.page
        assert "5 requests per 60 seconds" in page.locator("#banner-limit-title").inner_text()
        page.evaluate(COUNT_CHANGES)
        answer = dashboard.api("POST", "protection/throttle-all", json={"enabled": True, "limit": 50, "period": 60})
        assert answer.status_code == 200, answer.text
        assert eventually(page, "window.__changes >= 1", 15), "the stream reported the change"
        follows = eventually(
            page, "document.querySelector('#banner-limit-title').textContent.includes('50 requests per 60 seconds')", 10
        )
        assert follows, f"the banner still says: {page.locator('#banner-limit-title').inner_text()}"
    finally:
        dashboard.api("POST", "protection/throttle-all", json={"enabled": False})
        dashboard.change_settings(before)


# ============================================================================================ functional-8


# Fixed in the P11 review round (functional-8, shared fixer): a regression test now.
def test_staying_on_the_page_after_a_pause_shows_the_paused_state(open_admin: Any, dashboard: Any) -> None:
    try:
        admin = open_admin("/admin/cache")
        page = admin.page
        page.on("dialog", lambda dialog: dialog.dismiss())  # the browser's "Leave site?": the admin stays
        control = page.locator('form[data-setting-key="cache_ttl_seconds"]').first
        control.locator("[data-setting-input]").fill("4321")  # an edit not saved yet
        page.locator(".topbar__pause").click()
        admin.wait("document.querySelector('#dlg-pause').open")
        page.locator('#dlg-pause .dialog__foot button[type="submit"]').click()
        assert eventually(
            page, "[...document.querySelectorAll('.toast')].some((t) => t.textContent.includes('paused'))", 10
        )
        assert dashboard.api("GET", "protection/pause").json()["paused"] is True
        offers_resume = eventually(
            page,
            "document.querySelector('.topbar__pause').textContent.includes('Resume')"
            " || document.querySelector('#dlg-pause input[name=paused]').value === 'false'",
            10,
        )
        assert offers_resume, "the top bar still offers Pause, and its dialog would pause again"
    finally:
        dashboard.api("POST", "protection/pause", json={"paused": False})


# ============================================================================================ functional-10


# Fixed (fixer g7): static/js/pages/settings.js keeps the editor card's refresh address on its filter form, so the
# re-render after a batch save or an import shows the same search, filters and page. A regression test now.
def test_the_settings_editor_keeps_its_search_after_a_batch_save(open_admin: Any, dashboard: Any) -> None:
    key = "tarpit_max_concurrent"
    before = value_of(dashboard, key)
    try:
        admin = open_admin("/admin/settings?q=tarpit")
        page = admin.page
        page.locator(f'#editor-results form[data-setting-key="{key}"] [data-setting-input]').fill(str(int(before) + 1))
        admin.wait("!document.querySelector('[data-settings-batch]').hidden")
        page.locator('[data-action="settings-review"]').click()
        admin.wait("document.querySelector('#settings-batch-dialog[open] [data-batch-key]') !== null")
        page.locator("[data-batch-save]").click()
        assert eventually(
            page, "[...document.querySelectorAll('.toast')].some((t) => t.textContent.includes('Saved'))", 10
        )
        page.wait_for_timeout(2000)
        shown = page.eval_on_selector_all(
            "#editor-results form[data-setting-key]", "(forms) => forms.map((form) => form.dataset.settingKey)"
        )
        search = page.locator("#editor-filter input[name=q]").input_value()
        where = f"after the save the editor shows {shown} with the search box {search!r} (address {page.url})"
        assert search == "tarpit", where
        assert shown, where
        assert all("tarpit" in item for item in shown), where
    finally:
        dashboard.change_settings({key: before})


# ============================================================================================ functional-11


# Fixed in the P11 review round (functional-11, shared fixer): a regression test now.
def test_the_recommendations_count_follows_a_dismiss(open_admin: Any, dashboard: Any) -> None:
    listing = dashboard.api("GET", "recommendations", params={"state": "open"}).json()
    open_before = int(listing["total"])
    rec = listing["items"][0]["id"]
    admin = open_admin(f"/admin/recommendations?rec={rec}")
    page = admin.page
    admin.wait("document.querySelector('#drawer[open] [data-action=\"recommendation-dismiss\"]') !== null")
    assert f"{open_before} open" in (page.locator(".topbar__recs").get_attribute("aria-label") or "")
    page.locator('#drawer [data-action="recommendation-dismiss"]').click()
    assert eventually(
        page, "[...document.querySelectorAll('.toast')].some((t) => t.textContent.includes('Dismissed'))", 10
    )
    assert int(dashboard.api("GET", "recommendations", params={"state": "open"}).json()["total"]) == open_before - 1
    follows = eventually(
        page,
        "(document.querySelector('.topbar__recs').getAttribute('aria-label') || '')"
        f".includes('{open_before - 1} open')",
        10,
    )
    assert follows, f"the bell still says: {page.locator('.topbar__recs').get_attribute('aria-label')}"


# ============================================================================================ functional-12


# Fixed in the P11 review round (functional-12, shared fixer): a regression test now.
def test_the_live_range_follows_new_requests(open_admin: Any, dashboard: Any) -> None:
    admin = open_admin("/admin/traffic?range=live")
    page = admin.page
    first = "document.querySelector('#requests .traffic-stats__number').textContent.trim()"
    shown = page.evaluate(first)
    statuses = dashboard.send_traffic()  # the harness's plan through the real proxy, about a minute's worth of callers
    assert statuses, "requests went through Roxy"
    dashboard.flush()
    fresh = dashboard.get("/admin/traffic/fragment/requests", params={"range": "live"}).text
    assert f'traffic-stats__number">{shown}<' not in fresh, "the server's own card already has the new total"
    moved = eventually(page, f"{first} !== {shown!r}", 30)
    assert moved, f"30 s after {len(statuses)} more requests the Live range still shows {shown} (no reload, no refresh)"
