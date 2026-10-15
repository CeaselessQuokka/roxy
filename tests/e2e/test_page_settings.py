"""The Settings page in a real browser: clean, accessible, and the editor's flows work end to end.

What this is
    Browser tests against the real app (`dashboard`, tests/e2e/conftest.py). For each theme and size (1440x900 and
    390x844, dark and light) the page loads with its lazy history, no console error, page error or CSP violation,
    axe-core finds nothing serious, the phone never scrolls sideways, and a screenshot is saved for the visual review.
    Then the flows of plan 15.2: search and filters swap the results in place and keep the address, `#<key>` opens
    that setting, one setting saves inline after its review, a batch of edits is reviewed and saved with one reason, a
    high-risk change needs a reason and the confirmation, a batch holding an admin security setting asks "Confirm it
    is you" first, a history row reverts its change from the drawer, and an import shows its preview before it
    imports. Every test that changes a setting puts it back in a `finally`.

Why it exists
    The integration tests prove what the server sends and that the API refuses what it must; only a browser proves the
    page's scripts (static/js/pages/settings.js, the shared setting control) drive those flows under the strict CSP.

What to read next
    tests/integration/pages/test_page_settings.py, roxy/admin/pages/settings.py, static/js/pages/settings.js.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import pytest

from pages_harness import SESSION_COOKIE_NAME, THEMES, VIEWPORTS
from roxy.admin.pages.settings import DEFAULT_EDITOR_SIZE

PAGE = "/admin/settings"
CONTROLS = "#editor-results form[data-setting-key]"
MULTILINE_KEY = "site_hosting_note"
"""A string setting whose default has paragraphs (three public site texts do)."""
MULTILINE_BUG = (
    "the shared setting control (templates/components/setting.html) must render a long or multi-line string setting "
    "as a <textarea>: a one-line <input> drops the line breaks, so the public site texts would look edited the moment "
    "the page opens and a save would flatten their paragraphs"
)


def toast_says(text: str) -> str:
    return f"[...document.querySelectorAll('.toast')].some((toast) => toast.textContent.includes({json.dumps(text)}))"


def multiline_bug(dashboard: Any) -> bool:
    """True when the shared control renders a multi-line string setting as a one-line input (see MULTILINE_BUG)."""
    html = dashboard.get(f"{PAGE}/fragment/public-site").text
    marker = f'id="set-public-site-{MULTILINE_KEY}-value"'
    start = html.find(marker)
    assert start != -1, "the public site card holds the multi-line setting"
    tag_start = html.rfind("<", 0, start)
    return html[tag_start : tag_start + 9] != "<textarea"


def value_of(dashboard: Any, key: str) -> Any:
    return dashboard.api("GET", f"settings/{key}").json()["setting"]["value"]


@contextmanager
def restored(dashboard: Any, *keys: str) -> Iterator[dict[str, Any]]:
    """The values of `keys` now; they are put back afterwards (the dashboard is shared by every browser test)."""
    before = {key: value_of(dashboard, key) for key in keys}
    try:
        yield before
    finally:
        dashboard.change_settings(before)


def keep_new_session(dashboard: Any, page: Any) -> None:
    """A fresh second factor rotates the session cookie: hand the browser's new one back to the shared fixture."""
    for cookie in page.context.cookies():
        if cookie["name"] == SESSION_COOKIE_NAME:
            dashboard.signed_in.cookie = cookie["value"]


def shown_keys(page: Any) -> list[str]:
    return list(page.eval_on_selector_all(CONTROLS, "(forms) => forms.map((form) => form.dataset.settingKey)"))


def load_lazy(admin: Any) -> Any:
    """Every lazy card loaded and htmx idle (the shared settle), then back to the top."""
    admin.settle()
    return admin


def open_page(open_admin: Any, path: str = PAGE, **options: Any) -> Any:
    """`open_admin` (its settle step waits until every lazy card has loaded, `tests/e2e/conftest.py`)."""
    return open_admin(path, **options)


def poll(page: Any, expression: str, timeout_s: float = 10.0) -> None:
    """Wait for a JavaScript expression without waiting for the lazy cards (they load after a redirect)."""
    for _ in range(int(timeout_s * 20)):
        if page.evaluate(expression):
            return
        page.wait_for_timeout(50)
    raise AssertionError(f"timed out waiting for: {expression}")


@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("size", list(VIEWPORTS))
def test_the_page_is_clean_accessible_and_fits(open_admin: Any, theme: str, size: str) -> None:
    width, height = VIEWPORTS[size]
    admin = open_page(open_admin, PAGE, theme=theme, width=width, height=height)
    page = admin.page
    assert page.locator(CONTROLS).count() == DEFAULT_EDITOR_SIZE
    assert page.locator(".page-card--lazy").count() == 0  # the history loaded
    assert page.locator('#history [data-table="settings_history"]').count() == 1
    assert page.locator("#alerts [data-setting-key]").count() >= 1
    assert page.locator("#public-site [data-setting-key]").count() >= 1
    assert not admin.overflows(), "the page scrolls sideways"
    assert admin.axe() == []
    admin.shot("settings")
    admin.assert_clean()


@pytest.mark.parametrize("theme", THEMES)
def test_the_one_setting_view_is_clean_and_lists_its_history(open_admin: Any, dashboard: Any, theme: str) -> None:
    with restored(dashboard, "cache_ttl_seconds") as before:
        dashboard.change_settings({"cache_ttl_seconds": int(before["cache_ttl_seconds"]) + 5})
        dashboard.change_settings({"cache_ttl_seconds": int(before["cache_ttl_seconds"]) + 6})
        for width, height in VIEWPORTS.values():
            admin = open_page(open_admin, f"{PAGE}?key=cache_ttl_seconds", theme=theme, width=width, height=height)
            page = admin.page
            assert shown_keys(page) == ["cache_ttl_seconds"]
            assert page.locator("[data-key-history] li").count() >= 2
            assert not admin.overflows(), "the page scrolls sideways"
            assert admin.axe() == []
            admin.shot("settings-key")
            admin.assert_clean()
        page.locator("[data-key-history] button[data-drawer-src]").first.click()
        admin.wait("document.querySelector('#drawer[open] form.settings-revert') !== null")
        assert page.locator("#drawer-title").inner_text().startswith("Settings change #")
        assert admin.axe() == []
        admin.assert_clean()


def test_search_filters_and_pages_swap_the_results_and_keep_the_address(open_admin: Any, dashboard: Any) -> None:
    admin = open_page(open_admin, PAGE)
    page = admin.page
    page.evaluate("window.__sameDocument = true")
    page.fill("#editor-q", "tarpit")
    admin.wait("new URL(location.href).searchParams.get('q') === 'tarpit'")
    admin.wait("document.querySelector('[data-editor-status]').textContent.includes('best matches first')")
    assert "tarpit" in shown_keys(page)[0]
    page.fill("#editor-q", "")
    admin.wait("!new URL(location.href).searchParams.has('q')")
    page.select_option('#editor-filter select[name="group"]', "cache")
    admin.wait("new URL(location.href).searchParams.get('group') === 'cache'")
    listing = dashboard.api("GET", "settings", params={"group": "cache", "include_text": "false"}).json()
    expected = [entry["key"] for group in listing["groups"] for entry in group["settings"]]
    admin.wait(
        f"document.querySelectorAll({json.dumps(CONTROLS)}).length === {min(DEFAULT_EDITOR_SIZE, len(expected))}"
    )
    assert shown_keys(page) == expected[:DEFAULT_EDITOR_SIZE]
    if len(expected) > DEFAULT_EDITOR_SIZE:
        page.locator('[data-editor-goto="2"]').first.click()
        admin.wait("new URL(location.href).searchParams.get('page') === '2'")
        next_key = json.dumps(expected[DEFAULT_EDITOR_SIZE])
        admin.wait(f"document.querySelector({json.dumps(CONTROLS)}).dataset.settingKey === {next_key}")
    page.select_option('#editor-filter select[name="group"]', "")
    admin.wait("!new URL(location.href).searchParams.has('group')")
    assert page.evaluate("window.__sameDocument === true"), "a filter reloaded the whole page"
    admin.assert_clean()


def test_no_setting_looks_edited_when_the_page_opens(open_admin: Any, dashboard: Any) -> None:
    """Nothing is unsaved on a fresh page: no Save area open, no "Leave site?" question, shortcuts work."""
    assert not multiline_bug(dashboard), MULTILINE_BUG
    admin = open_page(open_admin, PAGE)
    dirty = admin.page.eval_on_selector_all(".setting[data-dirty]", "(forms) => forms.map((f) => f.dataset.settingKey)")
    assert dirty == []
    admin.assert_clean()


def test_a_hash_link_to_a_setting_opens_it(open_admin: Any, dashboard: Any) -> None:
    admin = open_admin(f"{PAGE}#tarpit_max_seconds", settle=False)
    poll(admin.page, "new URL(location.href).searchParams.get('key') === 'tarpit_max_seconds'")
    poll(admin.page, "document.querySelector('#tarpit_max_seconds form[data-setting-key]') !== null")
    load_lazy(admin)
    assert shown_keys(admin.page) == ["tarpit_max_seconds"]
    admin.assert_clean()  # no "edited" setting on the page that redirected, so no refused leave question either


def test_one_setting_saves_inline_after_its_review(open_admin: Any, dashboard: Any) -> None:
    with restored(dashboard, "cache_ttl_seconds") as before:
        target = int(before["cache_ttl_seconds"]) + 7
        admin = open_page(open_admin, f"{PAGE}?key=cache_ttl_seconds")
        page = admin.page
        control = page.locator('#editor-results form[data-setting-key="cache_ttl_seconds"]')
        control.locator("[data-setting-input]").fill(str(target))
        control.locator('input[name="reason"]').fill("Browser test of the editor")
        control.locator('button[type="submit"]').click()
        admin.wait("!document.querySelector('#editor-results [data-setting-review]').hidden")
        assert str(target) in control.locator("[data-setting-review]").inner_text()
        page.locator('#editor-results form[data-setting-key="cache_ttl_seconds"] button[type="submit"]').click()
        admin.wait("document.querySelector('#editor-results .setting__saved') !== null")
        assert int(value_of(dashboard, "cache_ttl_seconds")) == target
        admin.wait("document.querySelector('[data-settings-batch]').hidden")  # nothing left unsaved
        admin.assert_clean()


def _two_low_risk_numbers(dashboard: Any) -> list[dict[str, Any]]:
    listing = dashboard.api("GET", "settings", params={"group": "cache", "include_text": "false"}).json()
    chosen = []
    for group in listing["groups"]:
        for entry in group["settings"][:DEFAULT_EDITOR_SIZE]:
            numeric = entry["type"] in ("int", "duration") and entry["min"] is not None and entry["max"] is not None
            if numeric and entry["risk"] == "low" and not entry["needs_fresh_mfa"] and entry["max"] > entry["min"]:
                chosen.append(entry)
    return chosen[:2]


def test_a_batch_of_edits_is_reviewed_and_saved_with_one_reason(open_admin: Any, dashboard: Any) -> None:
    entries = _two_low_risk_numbers(dashboard)
    assert len(entries) == 2
    keys = [entry["key"] for entry in entries]
    with restored(dashboard, *keys) as before:
        targets = {}
        for entry in entries:
            value = int(before[entry["key"]])
            targets[entry["key"]] = value + 1 if value + 1 <= entry["max"] else value - 1
        admin = open_page(open_admin, f"{PAGE}?group=cache")
        page = admin.page
        for key, target in targets.items():
            page.locator(f'{CONTROLS}[data-setting-key="{key}"] [data-setting-input]').fill(str(target))
        admin.wait("!document.querySelector('[data-settings-batch]').hidden")
        assert page.locator("[data-batch-count]").inner_text().startswith("2 unsaved changes")
        page.locator('[data-action="settings-review"]').click()
        admin.wait("document.querySelectorAll('#settings-batch-dialog[open] [data-batch-key]').length === 2")
        assert not page.locator("[data-batch-save]").is_disabled()
        assert admin.axe() == []
        admin.shot("settings-batch")
        page.fill("#settings-batch-reason", "Browser test of a batch")
        page.locator("[data-batch-save]").click()
        admin.wait(toast_says("Saved 2 settings"))
        for key, target in targets.items():
            assert int(value_of(dashboard, key)) == target
        changes = dashboard.api("GET", "settings/history", params={"q": "Browser test of a batch"}).json()
        assert changes["total"] == 2
        admin.assert_clean()


def test_a_high_risk_change_needs_a_reason_and_the_confirmation(open_admin: Any, dashboard: Any) -> None:
    key = "public_cors_allow_any_origin"
    with restored(dashboard, key):
        dashboard.change_settings({key: 0})
        admin = open_page(open_admin, f"{PAGE}?key={key}")
        page = admin.page
        page.locator(f'{CONTROLS}[data-setting-key="{key}"] label.switch').click()
        admin.wait("!document.querySelector('[data-settings-batch]').hidden")
        page.locator('[data-action="settings-review"]').click()
        admin.wait("document.querySelector('#settings-batch-dialog[open] [data-batch-key]') !== null")
        admin.wait("!document.querySelector('[data-batch-confirm]').hidden")
        assert "required" in page.locator("[data-batch-reason-hint]").inner_text()
        page.locator("[data-batch-save]").click()
        admin.wait("!document.querySelector('[data-batch-reason-error]').hidden")
        page.fill("#settings-batch-reason", "Browser test of a high-risk change")
        page.locator("[data-batch-save]").click()
        admin.wait("/Tick the confirmation/.test(document.querySelector('[data-batch-error]').textContent)")
        assert int(value_of(dashboard, key)) == 0  # nothing was sent yet
        page.locator("[data-batch-confirm-box]").check()
        page.locator("[data-batch-save]").click()
        admin.wait(toast_says("Saved 1 setting"))
        assert int(value_of(dashboard, key)) == 1
        admin.assert_clean()


def test_an_admin_security_setting_asks_for_the_code_first(open_admin: Any, dashboard: Any) -> None:
    key = "admin_heartbeat_interval_s"
    with restored(dashboard, key) as before:
        target = int(before[key]) + 1
        window = value_of(dashboard, "admin_reauth_window_s")
        dashboard.clock.advance(int(window) + 1)  # the session lives on (idle timeout 900 s); its factor is old
        admin = open_page(open_admin, f"{PAGE}?key={key}")
        page = admin.page
        try:
            page.locator(f'{CONTROLS}[data-setting-key="{key}"] [data-setting-input]').fill(str(target))
            page.locator('[data-action="settings-review"]').click()
            admin.wait("!document.querySelector('#settings-batch-dialog[open] [data-batch-mfa]').hidden")
            page.locator("[data-batch-save]").click()
            admin.wait("document.querySelector('#reauth[open]') !== null")
            page.fill("#reauth-code", dashboard.next_code())
            page.locator('#reauth button[type="submit"]').click()
            try:
                # After the reauth dialog's own "Confirmed." toast. Moving the clock past the factor's window also
                # starts the scheduled jobs that were due (a health run among them), so the box is busy: 30 s.
                admin.wait(toast_says("Saved 1 setting"), timeout=30.0)
            except AssertionError:
                said = page.evaluate("document.querySelector('[data-batch-error]').textContent")
                raise AssertionError(f"no save toast; the review dialog says {said!r}") from None
        finally:
            keep_new_session(dashboard, page)
        assert int(value_of(dashboard, key)) == target
        admin.assert_clean()


def test_a_history_row_reverts_its_change_from_the_drawer(open_admin: Any, dashboard: Any) -> None:
    with restored(dashboard, "cache_ttl_seconds") as before:
        old = int(before["cache_ttl_seconds"])
        dashboard.change_settings({"cache_ttl_seconds": old + 3})
        admin = open_page(open_admin, PAGE)
        page = admin.page
        newest = dashboard.api("GET", "settings/history").json()["items"][0]
        assert newest["key"] == "cache_ttl_seconds"
        page.locator(f'#history tr[data-row-id="change-{newest["id"]}"] [data-dt-open]').click()
        admin.wait("document.querySelector('#drawer[open] form.settings-revert') !== null")
        assert page.locator("#drawer-title").inner_text().strip() == f"Settings change #{newest['id']}"
        page.fill("#drawer form.settings-revert textarea[name=reason]", "Browser test of a revert")
        page.locator('#drawer [data-action="settings-revert"]').click()
        admin.wait(toast_says("Reverted"))
        assert int(value_of(dashboard, "cache_ttl_seconds")) == old
        admin.assert_clean()


def test_an_import_shows_its_preview_then_imports_with_a_reason(open_admin: Any, dashboard: Any) -> None:
    with restored(dashboard, "cache_ttl_seconds") as before:
        target = int(before["cache_ttl_seconds"]) + 9
        exported = dashboard.api("GET", "settings/export").json()
        document = {**exported, "overrides": {**exported["overrides"], "cache_ttl_seconds": target}}
        admin = open_page(open_admin, PAGE)
        page = admin.page
        card = page.locator("section#import-export")
        card.locator("details summary").click()
        page.fill("#settings-import-text", json.dumps(document))
        card.locator('[data-action="settings-import-preview"]').click()
        admin.wait("!document.querySelector('[data-import-result]').hidden")
        assert "1 change to import" in card.locator("[data-import-summary]").inner_text()
        assert "Will change" in card.locator("[data-import-rows]").inner_text()
        assert int(value_of(dashboard, "cache_ttl_seconds")) == int(before["cache_ttl_seconds"])
        assert admin.axe() == []
        page.fill("#settings-import-reason", "Browser test of an import")
        card.locator('[data-action="settings-import"]').click()
        admin.wait(toast_says("Imported 1 change"))
        assert int(value_of(dashboard, "cache_ttl_seconds")) == target
        admin.assert_clean()


def test_an_import_redraws_the_editor_on_the_same_filters_and_page(open_admin: Any, dashboard: Any) -> None:
    """Finding functional-10 (the import half; the batch save half is tests/review_p11/test_functional_e2e.py): the
    editor card re-rendered after an import keeps its group filter, its page and the address."""
    listing = dashboard.api("GET", "settings", params={"group": "cache", "include_text": "false"}).json()
    expected = [entry["key"] for group in listing["groups"] for entry in group["settings"]]
    assert len(expected) > DEFAULT_EDITOR_SIZE, "the cache group has a second page of settings"
    second_page = expected[DEFAULT_EDITOR_SIZE : DEFAULT_EDITOR_SIZE * 2]
    with restored(dashboard, "cache_ttl_seconds") as before:
        exported = dashboard.api("GET", "settings/export").json()
        overrides = {**exported["overrides"], "cache_ttl_seconds": int(before["cache_ttl_seconds"]) + 4}
        admin = open_page(open_admin, f"{PAGE}?group=cache&page=2")
        page = admin.page
        assert shown_keys(page) == second_page
        # Every re-render of the card (an import, a batch save, a revert from the history drawer) asks this address.
        src = page.evaluate("new URL(document.getElementById('editor').dataset.cardSrc, location.origin).search")
        assert "group=cache" in src, src
        assert "page=2" in src, src
        page.evaluate("document.getElementById('editor').__drawnBefore = true")
        card = page.locator("section#import-export")
        card.locator("details summary").click()
        page.fill("#settings-import-text", json.dumps({**exported, "overrides": overrides}))
        card.locator('[data-action="settings-import-preview"]').click()
        admin.wait("!document.querySelector('[data-import-result]').hidden")
        page.fill("#settings-import-reason", "Browser test of an import on page 2")
        card.locator('[data-action="settings-import"]').click()
        admin.wait(toast_says("Imported 1 change"))
        admin.wait("document.getElementById('editor').__drawnBefore !== true")  # the card was drawn again
        where = f"after the import the editor shows {shown_keys(page)} (address {page.url})"
        assert shown_keys(page) == second_page, where
        assert page.locator('#editor-filter select[name="group"]').input_value() == "cache", where
        assert page.evaluate("new URL(location.href).searchParams.get('group')") == "cache", where
        assert page.evaluate("new URL(location.href).searchParams.get('page')") == "2", where
        admin.assert_clean()
