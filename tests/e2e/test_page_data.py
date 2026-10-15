"""The Data page in a real browser: clean, accessible, fits a phone, and its controls work.

What this is
    Browser tests against the real app (`dashboard`, tests/e2e/conftest.py: a free port, an admin signed in through
    the real password and TOTP steps, seeded traffic). For each theme and size the page loads with no console error,
    page error or CSP violation, axe-core finds nothing serious, the phone layout never scrolls sideways, every card
    (the lazy ones too) loads without an error card, and screenshots are saved for the visual review (the whole page,
    plus one crop per card under `shots/g6_cards/`). Then the controls: a table opens in the drawer with its limits;
    the reset form shows only the fields of the chosen scope; a reset is previewed, then run with the typed phrase
    the preview names, and says it is done; Back up now says what it asked and copied; VACUUM stays off until its
    phrase is typed and then reports what it gave back; an inline retention setting is reviewed and saved; a dataset
    downloads as CSV and the LLM export copies to the clipboard.

Why it exists
    The integration tests prove what the server sends; only a browser proves the page works under the strict CSP
    with htmx, the dialogs and the page script (static/js/pages/data.js).

What to read next
    tests/integration/pages/test_page_data.py, roxy/admin/pages/data.py, static/js/pages/data.js.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from pages_harness import THEMES, VIEWPORTS

PAGE = "/admin/data"
CARD_SHOTS = Path(__file__).resolve().parents[2] / ".remake" / "p11_reports" / "shots" / "g6_cards"
NO_ERROR_CARD = "() => !document.querySelector('[data-card-error]') && !document.querySelector('.page-card--lazy')"


def shoot_cards(admin: Any, page_id: str) -> list[str]:
    """One screenshot per card (a long card: its first screen and the whole card); returns the card ids shot."""
    CARD_SHOTS.mkdir(parents=True, exist_ok=True)
    page = admin.page
    ids: list[str] = page.evaluate("[...document.querySelectorAll('main section[data-card]')].map((s) => s.id)")
    stem = f"{page_id}_{admin.theme}_{admin.width}"
    page.locator("main .page-header").screenshot(path=str(CARD_SHOTS / f"{stem}_header.png"))
    for card_id in ids:
        locator = page.locator(f"main section#{card_id}").first
        locator.scroll_into_view_if_needed()
        admin.settle()
        box = locator.bounding_box()
        assert box is not None, f"{card_id} is not on the page"
        assert box["height"] > 40, f"{card_id} is empty"
        locator.screenshot(path=str(CARD_SHOTS / f"{stem}_{card_id}.png"))
    return ids


@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("size", list(VIEWPORTS))
def test_the_page_is_clean_accessible_and_fits(open_admin: Any, theme: str, size: str) -> None:
    width, height = VIEWPORTS[size]
    admin = open_admin(PAGE, theme=theme, width=width, height=height)
    page = admin.page
    assert page.locator(f'html[data-theme="{theme}"]').count() == 1
    assert page.evaluate(NO_ERROR_CARD)
    assert page.locator('#storage [data-table="storage_tables"] tbody tr[data-row-id]').count() > 0
    assert page.locator("#storage [data-kpi]").count() == 4
    assert page.locator("#retention [data-setting-key]").count() > 0
    assert page.locator("#record-caps [data-setting-key]").count() > 0
    assert page.locator("#exports [data-setting-key]").count() > 0
    assert page.locator("#resets form[data-reset-form]").count() == 1
    assert page.locator("#exports a[data-export]").count() > 0
    assert page.locator('#vacuum [data-action="vacuum-control"]').count() == 1
    assert not admin.overflows(), "the page scrolls sideways"
    assert admin.axe() == []
    admin.shot("data")
    ids = shoot_cards(admin, "data")
    assert set(ids) >= {"storage", "retention", "record-caps", "resets", "backups", "vacuum", "exports"}
    assert not admin.overflows(), "a card scrolls the page sideways"
    admin.assert_clean()


def test_a_table_opens_in_the_drawer_with_its_limits(open_admin: Any) -> None:
    admin = open_admin(PAGE, theme="light")
    page = admin.page
    page.fill("#data-storage-q", "events")
    rows = "[...document.querySelectorAll('#data-storage tbody tr[data-row-id]')]"
    # The search matches the database and table names too (hidden columns on a phone), so the rows left are few.
    admin.wait(
        f"{rows}.length > 0 && {rows}.length < 10 && {rows}.some((r) => r.dataset.rowId === 'table-metrics-events')"
    )
    row = page.locator('#data-storage tbody tr[data-row-id="table-metrics-events"]')
    assert row.count() == 1
    row.click()
    admin.wait("document.querySelector('#drawer[open] [data-storage-detail]') !== null")
    assert page.locator("#drawer-title").inner_text().strip() == "metrics.events"
    drawer = page.locator("#drawer [data-storage-detail]")
    assert "Rows are kept for" in drawer.inner_text()
    hrefs = [drawer.locator("a.data-setting-ref").nth(i).get_attribute("href") for i in range(2)]
    assert "/admin/settings?key=retention_events_days" in hrefs
    assert admin.axe() == []
    admin.shot("data-drawer")
    CARD_SHOTS.mkdir(parents=True, exist_ok=True)
    page.screenshot(path=str(CARD_SHOTS / f"data-drawer_{admin.theme}_{admin.width}.png"))  # what the eye sees
    page.keyboard.press("Escape")
    admin.wait("!document.querySelector('#drawer[open]')")
    admin.assert_clean()


def test_the_reset_form_shows_only_the_fields_of_its_scope(open_admin: Any) -> None:
    admin = open_admin(PAGE)
    page = admin.page
    families = '#resets fieldset[data-scope-fields="family date_range"]'
    assert page.locator(families).is_visible()
    assert page.locator('#resets fieldset[data-scope-fields="bans"]').is_hidden()
    page.select_option("#reset-scope", "bans")
    assert page.locator('#resets fieldset[data-scope-fields="bans"]').is_visible()
    assert page.locator(families).is_hidden()
    assert "ban" in page.locator("#reset-scope-desc").inner_text().lower()
    page.select_option("#reset-scope", "endpoint")
    assert page.locator('#resets fieldset[data-scope-fields="endpoint"]').is_visible()
    assert page.locator('#resets fieldset[data-scope-fields="bans"]').is_hidden()
    # A preview of an endpoint scope without a template is refused with the field's own message.
    page.locator('#resets [data-action="reset-preview"]').click()
    admin.wait(
        "!document.querySelector('#reset-template-error').hidden"
        " || !document.querySelector('[data-reset-error]').hidden"
    )
    assert page.locator("[data-reset-preview]").is_hidden()
    admin.assert_clean(expected=["status of 422"])


def test_a_reset_is_previewed_then_runs_with_the_typed_phrase(open_admin: Any, dashboard: Any) -> None:
    admin = open_admin(PAGE)
    page = admin.page
    page.select_option("#reset-scope", "family")
    page.locator('#resets input[name="families"][value="crawls"]').check()
    page.locator('#resets [data-action="reset-preview"]').click()
    admin.wait("!document.querySelector('[data-reset-preview]').hidden")
    preview = page.locator("[data-reset-preview]")
    assert preview.locator("[data-preview-summary]").inner_text().strip()
    assert preview.locator("[data-preview-tables] tr").count() >= 1
    assert admin.axe() == []
    page.locator('[data-action="reset-open-run"]').click()
    admin.wait("document.querySelector('#dlg-reset-run[open]') !== null")
    dialog = page.locator("#dlg-reset-run")
    assert dialog.locator("[data-reset-run-phrase-text]").inner_text() == "reset crawls"
    submit = dialog.locator("[data-reset-run-submit]")
    assert submit.is_disabled()
    dialog.locator('textarea[name="reason"]').fill("Browser test of the reset flow")
    dialog.locator('input[name="confirm"]').fill("reset crawl")
    assert submit.is_disabled()
    dialog.locator('input[name="confirm"]').fill("reset crawls")
    assert submit.is_enabled()
    assert admin.axe() == []
    submit.click()
    admin.wait("/is done/.test((document.querySelector('[data-reset-result]') || {}).innerText || '')", timeout=30)
    result = page.locator("[data-reset-result]")
    assert result.locator("a").get_attribute("href").startswith("/admin/audit?entry=")
    assert page.locator("#dlg-reset-run[open]").count() == 0
    audit = dashboard.api("GET", "audit", params={"action": "data.reset.done"}).json()
    assert audit["total"] >= 1
    admin.assert_clean()


def test_back_up_now_says_what_it_asked_and_copied(open_admin: Any) -> None:
    admin = open_admin(PAGE)
    page = admin.page
    page.locator('.page-header [data-action="backup-now"]').click()
    admin.wait("document.querySelector('#dlg-backup[open]') !== null")
    assert admin.axe() == []
    page.fill("#dlg-backup-reason", "Browser test of Back up now")
    page.locator('#dlg-backup button[type="submit"]').click()
    admin.wait(
        "/Back up now finished/.test((document.querySelector('[data-op-result=\"backups\"]') || {}).innerText || '')",
        timeout=30,
    )
    words = page.locator('[data-op-result="backups"]').inner_text()
    assert "nightly backup was asked to run now" in words
    assert "Asked" in page.locator("#backups .data-backups__facts").inner_text()
    admin.assert_clean()


def test_vacuum_waits_for_its_phrase_then_reports_what_it_gave_back(open_admin: Any) -> None:
    admin = open_admin(PAGE)
    page = admin.page
    page.locator('#vacuum [data-action="vacuum-control"]').click()
    admin.wait("document.querySelector('#dlg-vacuum-control[open]') !== null")
    dialog = page.locator("#dlg-vacuum-control")
    submit = dialog.locator('button[type="submit"]')
    assert submit.is_disabled()
    dialog.locator('input[name="confirm"]').fill("vacuum control")
    admin.wait("!document.querySelector('#dlg-vacuum-control button[type=submit]').disabled")
    submit.click()
    admin.wait(
        "/VACUUM of control.db finished/.test("
        "(document.querySelector('[data-op-result=\"vacuum\"]') || {}).innerText || '')",
        timeout=60,
    )
    assert "It gave back" in page.locator('[data-op-result="vacuum"]').inner_text()
    admin.assert_clean()


def test_an_inline_retention_setting_is_reviewed_then_saved(open_admin: Any, dashboard: Any) -> None:
    key = "retention_events_days"
    before = int(dashboard.api("GET", f"settings/{key}").json()["setting"]["value"])
    admin = open_admin(PAGE)
    page = admin.page
    try:
        control = page.locator(f'#retention form[data-setting-key="{key}"]')
        control.scroll_into_view_if_needed()
        control.locator("[data-setting-input]").fill(str(before + 1))
        control.locator('input[name="reason"]').fill("Browser test of the inline editor")
        control.locator('button[type="submit"]').click()
        admin.wait(f"!document.querySelector('#set-retention-{key} [data-setting-review]').hidden")
        assert control.locator("[data-setting-submit-label]").inner_text().strip() == "Save"
        control.locator('button[type="submit"]').click()
        admin.wait(f"document.querySelector('#set-retention-{key} .setting__saved') !== null")
        saved = dashboard.api("GET", f"settings/{key}").json()["setting"]["value"]
        assert int(saved) == before + 1
        admin.assert_clean()
    finally:
        dashboard.change_settings({key: before})


def test_a_dataset_downloads_and_the_llm_export_copies(open_admin: Any, dashboard: Any) -> None:
    admin = open_admin(PAGE)
    page = admin.page
    link = page.locator('#exports [data-action="export-probes-csv"]')
    link.scroll_into_view_if_needed()
    with page.expect_download() as info:
        link.click()
    download = info.value
    assert download.suggested_filename.startswith("roxy_probes_")
    assert download.suggested_filename.endswith(".csv")
    page.context.grant_permissions(["clipboard-read", "clipboard-write"], origin=dashboard.base_url)
    page.locator('#exports [data-action="llm-copy"]').click()
    admin.wait("[...document.querySelectorAll('.toast')].some((t) => /Copied/.test(t.innerText))", timeout=30)
    text = page.evaluate("navigator.clipboard.readText()")
    assert len(text) > 100
    assert "Roxy" in text
    admin.assert_clean()
