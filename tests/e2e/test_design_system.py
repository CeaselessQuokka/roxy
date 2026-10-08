"""The dashboard design system in a real browser: accessibility, phone layout, and every component's behavior.

What this is
    Playwright tests against the development component gallery (/admin/_gallery, roxy/admin/gallery.py), which
    renders every component of templates/components inside the real admin shell (templates/admin/base.html).

Why it exists
    Plan 14.9 and 19.8: zero serious or critical axe-core violations in light and dark themes at phone (390x844)
    and desktop (1440x900) sizes; keyboard operation of the command palette, dialogs and the settings control;
    plan 14.8: the phone layout uses a bottom bar and a bottom sheet with 44 px targets and never scrolls sideways;
    plan 9.6 and parity row 119: heartbeats only after real input, and the session-expired overlay on any 401.
    The components are also exercised end to end (server-side table paging, setting validation and save, the SSE
    tail resuming from Last-Event-ID) because the dashboard pages built on them in P11 part two depend on it.

How it works
    `ui_server` and `open_page` come from tests/e2e/conftest.py; `wait_js` polls without eval (the strict CSP
    forbids it); `axe` runs the vendored axe-core 4.13.0 through the DevTools protocol. Phone tests use a touch
    context (`is_mobile`, `has_touch`), so the `pointer: coarse` rules apply as on a real phone. Gallery counters
    (`/admin/_gallery/stats`) are shared by the session, so tests compare before and after values. Screenshots for
    review are written to docs/screenshots/ only when ROXY_SCREENSHOTS=1.

What to read next
    tests/e2e/test_csp_spike.py, src/roxy/admin/gallery.py, templates/admin/_gallery/index.html.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import pytest

from roxy.core.style_guard import find_style_issues

pytestmark = pytest.mark.e2e

GALLERY = "/admin/_gallery"
REPO = Path(__file__).resolve().parents[2]
PHONE = {"width": 390, "height": 844, "is_mobile": True, "has_touch": True}
DESKTOP = {"width": 1440, "height": 900}


def _open(
    ui_server: Any,
    open_page: Any,
    wait_js: Any,
    *,
    theme: str = "dark",
    query: str = "",
    size: dict[str, Any] | None = None,
    reduced_motion: str = "no-preference",
) -> Any:
    record = open_page(
        color_scheme="light" if theme == "light" else "dark", reduced_motion=reduced_motion, **(size or DESKTOP)
    )
    page = record.page
    response = page.goto(f"{ui_server.base_url}{GALLERY}?theme={theme}{query}")
    assert response is not None
    assert response.ok
    wait_js(page, "document.documentElement.dataset.ready === '1'")
    wait_js(page, "[...document.querySelectorAll('[data-chart]')].every(f => f.dataset.chartReady === '1')", 15)
    return record


def _escape(page: Any, wait_js: Any, dialog_id: str) -> None:
    """Press Escape and wait until the dialog has closed (Chrome closes a modal dialog one task after the key)."""
    page.keyboard.press("Escape")
    wait_js(page, f"!document.getElementById('{dialog_id}').open")


def _stats(page: Any, ui_server: Any) -> dict[str, Any]:
    result: dict[str, Any] = page.request.get(f"{ui_server.base_url}{GALLERY}/stats").json()
    return result


# ------------------------------------------------------------------------------------------- accessibility


@pytest.mark.parametrize(
    ("theme", "size"),
    [("dark", DESKTOP), ("light", DESKTOP), ("dark", PHONE), ("light", PHONE)],
    ids=["dark-1440x900", "light-1440x900", "dark-390x844", "light-390x844"],
)
def test_axe_finds_no_serious_or_critical_violations(
    ui_server: Any, open_page: Any, wait_js: Any, axe: Any, theme: str, size: dict[str, Any]
) -> None:
    # Reduced motion: axe measures contrast at once, and a dialog fading in would read as low contrast.
    record = _open(ui_server, open_page, wait_js, theme=theme, size=size, reduced_motion="reduce")
    violations = axe(record.page)
    assert violations == [], violations


def test_axe_is_clean_with_the_palette_a_dialog_and_the_drawer_open(
    ui_server: Any, open_page: Any, wait_js: Any, axe: Any
) -> None:
    record = _open(ui_server, open_page, wait_js, reduced_motion="reduce")
    page = record.page
    page.keyboard.press("Control+k")
    page.wait_for_selector("#palette[open]")
    page.keyboard.type("cache")
    assert axe(page) == []
    _escape(page, wait_js, "palette")
    page.click("[data-dialog-open='dlg-demo-purge']")
    page.wait_for_selector("#dlg-demo-purge[open]")
    assert axe(page) == []
    _escape(page, wait_js, "dlg-demo-purge")
    page.click("#gallery-endpoints tbody tr:first-child [data-dt-open]")
    page.wait_for_selector("#drawer[open] .kv")
    assert axe(page) == []


def test_skip_link_is_the_first_tab_stop_and_moves_focus_to_main(ui_server: Any, open_page: Any, wait_js: Any) -> None:
    page = _open(ui_server, open_page, wait_js).page
    page.keyboard.press("Tab")
    assert page.evaluate("document.activeElement.classList.contains('skip-link')")
    page.keyboard.press("Enter")
    assert page.evaluate("document.activeElement.id") == "main"


def test_desktop_targets_are_at_least_24_px(ui_server: Any, open_page: Any, wait_js: Any) -> None:
    page = _open(ui_server, open_page, wait_js).page
    small = page.evaluate(
        """() => [...document.querySelectorAll(
              'button, summary, select, a.btn, a.icon-btn, .nav-link, .menu__item, .legend-item, ' +
              'input:not([type=checkbox]):not([type=radio]):not([type=hidden])')]
            .filter(e => e.offsetParent !== null && !e.closest('dialog:not([open])'))
            .map(e => [e, e.getBoundingClientRect()])
            .filter(([e, r]) => r.width > 0 && (r.width < 23.5 || r.height < 23.5))
            .map(([e, r]) => `${e.tagName} ${e.className} ${Math.round(r.width)}x${Math.round(r.height)}`)"""
    )
    assert small == []


def test_rendered_gallery_passes_the_writing_style_check(ui_server: Any, open_page: Any, wait_js: Any) -> None:
    page = _open(ui_server, open_page, wait_js).page
    assert find_style_issues(page.content(), "gallery") == []


# ------------------------------------------------------------------------------------------- phone layout


def test_phone_layout_has_bottom_bar_44px_targets_and_no_sideways_scroll(
    ui_server: Any, open_page: Any, wait_js: Any
) -> None:
    page = _open(ui_server, open_page, wait_js, size=PHONE).page
    assert not page.is_visible("#sidebar")
    assert page.is_visible(".mobile-nav")
    assert page.evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth")
    targets = """sel => [...document.querySelectorAll(sel)].filter(e => e.offsetParent !== null)
                   .map(e => [e, e.getBoundingClientRect()])
                   .filter(([e, r]) => r.width < 43.5 || r.height < 43.5)
                   .map(([e, r]) => `${e.className} ${Math.round(r.width)}x${Math.round(r.height)}`)"""
    assert page.evaluate(targets, ".topbar a, .topbar button, .topbar summary, .mobile-nav a, .mobile-nav button") == []
    # The owner can pause from a phone (plan 14.8): the top bar keeps the Pause button.
    assert page.is_visible(".topbar__pause")
    page.click(".mobile-nav [data-dialog-open='nav-sheet']")
    page.wait_for_selector("#nav-sheet[open]")
    assert page.evaluate(targets, "#nav-sheet a, #nav-sheet button") == []
    assert page.is_visible("#nav-sheet a[href='/admin/recommendations']")
    _escape(page, wait_js, "nav-sheet")


def test_phone_tables_become_cards_with_key_columns(ui_server: Any, open_page: Any, wait_js: Any) -> None:
    page = _open(ui_server, open_page, wait_js, size=PHONE).page
    first_row = "#gallery-endpoints tbody tr:first-child"
    assert page.is_visible(f"{first_row} td[data-col='requests']")
    assert not page.is_visible(f"{first_row} td[data-col='hit_ratio']")  # not a key column: in the drawer
    page.click(f"{first_row} [data-dt-open]")
    page.wait_for_selector("#drawer[open] .kv")
    assert "Hit ratio" in page.text_content("#drawer-body")


# ------------------------------------------------------------------------------------------- shell behavior


def test_command_palette_and_shortcuts(ui_server: Any, open_page: Any, wait_js: Any) -> None:
    page = _open(ui_server, open_page, wait_js).page
    page.keyboard.press("Control+k")
    page.wait_for_selector("#palette[open]")
    assert page.evaluate("document.activeElement.id") == "palette-input"
    assert page.get_attribute("#palette-input", "aria-activedescendant") == "pal-page-overview"
    page.keyboard.press("ArrowDown")
    assert page.get_attribute("#palette-input", "aria-activedescendant") == "pal-page-recommendations"
    page.keyboard.type("settings")
    assert page.get_attribute("#palette-input", "aria-activedescendant") == "pal-page-settings"
    # The server adds matching settings and endpoints (at most 20).
    page.fill("#palette-input", "ttl")
    page.wait_for_selector("#palette-list [data-remote]")
    assert "Settings" in page.text_content("#palette-list")
    _escape(page, wait_js, "palette")
    page.keyboard.press("/")
    page.wait_for_selector("#palette[open]")
    _escape(page, wait_js, "palette")
    page.keyboard.press("?")
    page.wait_for_selector("#shortcuts[open]")
    assert "Go to a page" in page.text_content("#shortcuts")
    _escape(page, wait_js, "shortcuts")
    # Single-key shortcuts never fire while typing in a field.
    page.fill("#g-in-text", "")
    page.type("#g-in-text", "g s ?")
    assert page.evaluate("!document.getElementById('shortcuts').open")
    page.click("#main h1")
    page.keyboard.press("g")
    page.keyboard.press("s")
    page.wait_for_url(re.compile(r".*/admin/settings$"))


def test_theme_switch_changes_tokens_and_redraws_charts(ui_server: Any, open_page: Any, wait_js: Any) -> None:
    page = _open(ui_server, open_page, wait_js).page
    dark_bg = page.evaluate("getComputedStyle(document.body).backgroundColor")
    page.click(".user-menu > summary")
    page.click(".user-menu [data-theme-set='light']")
    assert page.get_attribute("html", "data-theme") == "light"
    assert page.get_attribute(".user-menu [data-theme-set='light']", "aria-pressed") == "true"
    light_bg = page.evaluate("getComputedStyle(document.body).backgroundColor")
    assert light_bg != dark_bg
    assert light_bg == "rgb(244, 245, 247)"
    wait_js(page, "[...document.querySelectorAll('[data-chart]')].every(f => f.dataset.chartReady === '1')")
    assert page.locator("#chart-traffic canvas").count() == 1


def test_sidebar_collapses_and_remembers(ui_server: Any, open_page: Any, wait_js: Any) -> None:
    record = _open(ui_server, open_page, wait_js)
    page = record.page
    page.click("[data-sidebar-toggle]")
    assert page.get_attribute("[data-shell]", "data-sidebar") == "collapsed"
    assert page.get_attribute("[data-sidebar-toggle]", "aria-expanded") == "false"
    page.reload()
    wait_js(page, "document.documentElement.dataset.ready === '1'")
    assert page.get_attribute("[data-shell]", "data-sidebar") == "collapsed"
    page.hover(".nav-link[data-nav-id='cache']")
    page.wait_for_selector("#roxy-tip:not([hidden])")
    assert page.text_content("#roxy-tip") == "Cache"


def test_how_to_read_panel_is_present_and_remembered(ui_server: Any, open_page: Any, wait_js: Any) -> None:
    page = _open(ui_server, open_page, wait_js).page
    assert page.locator("details#how-to-read").count() == 1
    page.click("#how-to-read > summary")
    page.reload()
    wait_js(page, "document.documentElement.dataset.ready === '1'")
    assert page.evaluate("document.getElementById('how-to-read').open")


def test_tooltips_for_help_dots_and_glossary_terms(ui_server: Any, open_page: Any, wait_js: Any) -> None:
    page = _open(ui_server, open_page, wait_js).page
    page.hover("#g-glossary .gloss >> nth=0")
    page.wait_for_selector("#roxy-tip:not([hidden])")
    assert "seconds to wait" in page.text_content("#roxy-tip")
    assert "roxy-tip" in (page.get_attribute("#g-glossary .gloss >> nth=0", "aria-describedby") or "")
    page.keyboard.press("Escape")
    assert page.evaluate("document.getElementById('roxy-tip').hidden")
    page.focus("#g-kpis .help-dot >> nth=0")
    page.wait_for_selector("#roxy-tip:not([hidden])")
    assert "Every proxy request" in page.text_content("#roxy-tip")
    assert page.get_attribute("#g-glossary .gloss >> nth=0", "href") == "/admin/help#term-retry-after"


# ------------------------------------------------------------------------------------------- session


def test_heartbeat_is_sent_only_after_real_input(ui_server: Any, open_page: Any, wait_js: Any) -> None:
    page = _open(ui_server, open_page, wait_js, query="&hb=1&aw=2").page
    start = _stats(page, ui_server)["heartbeats"]
    page.wait_for_timeout(2600)  # no input: an open but unattended tab sends nothing
    assert _stats(page, ui_server)["heartbeats"] == start
    page.mouse.move(400, 300)
    page.mouse.move(420, 320)
    sent = False
    for _ in range(40):
        if _stats(page, ui_server)["heartbeats"] > start:
            sent = True
            break
        page.wait_for_timeout(100)
    assert sent, "no heartbeat after input"
    stats = _stats(page, ui_server)
    assert all(isinstance(ms, int) and 0 <= ms <= 2000 for ms in stats["heartbeat_idle_ms"][-1:])
    page.wait_for_timeout(3200)  # the activity window (2 s) has passed since the last input
    settled = _stats(page, ui_server)["heartbeats"]
    page.wait_for_timeout(2500)
    assert _stats(page, ui_server)["heartbeats"] == settled


def test_session_expired_overlay_on_any_401_and_stay(ui_server: Any, open_page: Any, wait_js: Any) -> None:
    page = _open(ui_server, open_page, wait_js).page
    url = page.url
    page.click("#g-expire")
    page.wait_for_selector("#session-expired[open]")
    assert page.evaluate("document.activeElement.matches('[data-session-login]')")
    assert "Going to the login page in" in page.text_content("[data-session-countdown]")
    page.click("[data-session-stay]")
    assert page.evaluate("!document.getElementById('session-expired').open")
    page.wait_for_timeout(1500)
    assert page.url == url


def test_session_expired_overlay_redirects_to_login(ui_server: Any, open_page: Any, wait_js: Any) -> None:
    page = _open(ui_server, open_page, wait_js).page
    page.click("#g-expire")
    page.wait_for_selector("#session-expired[open]")
    page.wait_for_url(re.compile(r".*/admin$"), timeout=9000)


# ------------------------------------------------------------------------------------------- components


def test_htmx_requests_carry_the_csrf_header_and_server_toasts_show(
    ui_server: Any, open_page: Any, wait_js: Any
) -> None:
    page = _open(ui_server, open_page, wait_js).page
    page.click("#g-server-toast")
    page.wait_for_selector("#toasts .toast")
    assert "nothing changed" in page.text_content("#toasts")
    assert _stats(page, ui_server)["csrf_headers"][-1] is True
    wait_js(page, "document.getElementById('sr-polite').textContent.includes('nothing changed')")


def test_htmx_indicator_shows_while_loading(ui_server: Any, open_page: Any, wait_js: Any) -> None:
    page = _open(ui_server, open_page, wait_js).page
    page.click("#g-slow")
    page.wait_for_selector("#g-slow-spinner.htmx-request")
    page.wait_for_selector("#g-slow-out:has-text('Loaded at')")
    page.wait_for_selector("#g-slow-spinner:not(.htmx-request)")


def test_table_paging_sorting_search_and_columns(ui_server: Any, open_page: Any, wait_js: Any) -> None:
    page = _open(ui_server, open_page, wait_js).page
    count = "#gallery-endpoints .dt__count"
    assert re.sub(r"\s+", " ", page.text_content(count)).strip() == "Showing 1 to 10 of 44"
    page.click("#gallery-endpoints [aria-label='Next page']")
    wait_js(page, "document.querySelector('#gallery-endpoints .dt__count').textContent.includes('11 to 20')")
    page.click("#gallery-endpoints [data-dt-sort='p95']")
    wait_js(
        page,
        "document.querySelector(\"#gallery-endpoints th[data-col='p95']\").getAttribute('aria-sort') === 'descending'",
    )
    values = [
        int(v.replace(",", "").split()[0])
        for v in page.eval_on_selector_all(
            "#gallery-endpoints td[data-col='p95']", "els => els.map(e => e.textContent)"
        )
    ]
    assert values == sorted(values, reverse=True)
    assert "1 to 10" in page.text_content(count)  # a new sort starts again at page 1
    page.select_option("#gallery-endpoints [data-dt-size]", "25")
    wait_js(page, "document.querySelector('#gallery-endpoints .dt__count').textContent.includes('1 to 25')")
    page.fill("#gallery-endpoints-q", "thumbnails")
    wait_js(page, "document.querySelector('#gallery-endpoints .dt__count').textContent.includes('of 6')")
    assert page.evaluate("document.activeElement.id") == "gallery-endpoints-q"  # focus survives the swap
    endpoints = page.eval_on_selector_all(
        "#gallery-endpoints td[data-col='endpoint']", "els => els.map(e => e.textContent)"
    )
    assert endpoints
    assert all("thumbnails" in e for e in endpoints)
    page.click("#gallery-endpoints .dt__tools summary:has-text('Columns')")
    page.uncheck("#gallery-endpoints [data-dt-col='hit_ratio']")
    assert not page.is_visible("#gallery-endpoints th[data-col='hit_ratio']")
    page.reload()
    wait_js(page, "document.documentElement.dataset.ready === '1'")
    assert not page.is_visible("#gallery-endpoints th[data-col='hit_ratio']")  # remembered in this browser
    href = page.get_attribute("#gallery-endpoints a[href*='format=csv']", "href") or ""
    assert "/admin/_gallery/export?" in href


def test_row_details_open_in_the_drawer_and_return_focus(ui_server: Any, open_page: Any, wait_js: Any) -> None:
    page = _open(ui_server, open_page, wait_js).page
    opener = "#gallery-endpoints tbody tr:first-child [data-dt-open]"
    page.focus(opener)
    page.keyboard.press("Enter")
    page.wait_for_selector("#drawer[open] .kv")
    assert "Upstream calls" in page.text_content("#drawer-body")
    _escape(page, wait_js, "drawer")
    assert page.evaluate("document.activeElement.matches('[data-dt-open]')")


def test_setting_control_validates_previews_and_saves(ui_server: Any, open_page: Any, wait_js: Any) -> None:
    page = _open(ui_server, open_page, wait_js).page
    form = "#set-cache_ttl_seconds"
    field = f"{form}-value"
    page.fill(field, "banana")
    page.wait_for_selector(f"{form} .setting__error:not([hidden])")
    assert "duration" in page.text_content(f"{form} .setting__error")
    assert page.get_attribute(field, "aria-invalid") == "true"
    assert page.is_disabled(f"{form} button[type=submit]")
    page.fill(field, "15m")
    wait_js(page, f"document.querySelector('{form}-preview').textContent === '= 15 minutes'")
    assert page.get_attribute(field, "aria-invalid") == "false"
    page.wait_for_selector(f"{form} .setting__save", state="visible")
    page.click(f"{form} button[type=submit]")
    page.wait_for_selector(f"{form} .setting__saved")
    assert page.input_value(field) == "900"
    page.wait_for_selector("#toasts .toast:has-text('saved')")
    # Reset to default fills in the default and waits for a save (parity row 124).
    page.click(f"{form} .setting__links .link-btn")
    assert page.input_value(field) == "120"
    page.wait_for_selector(f"{form} .setting__save", state="visible")


def test_high_risk_setting_needs_a_reason_and_confirmation(ui_server: Any, open_page: Any, wait_js: Any) -> None:
    page = _open(ui_server, open_page, wait_js).page
    form = "#set-strict_host_allowlist"
    page.click(f"{form} .switch")
    page.wait_for_selector(f"{form} .setting__risk:not([hidden])")
    assert page.is_visible(f"{form} .setting__confirm")
    page.click(f"{form} button[type=submit]")  # no reason: the server refuses it too
    page.wait_for_selector(f"{form} .setting__error:not([hidden])")
    assert "high-risk" in page.text_content(f"{form} .setting__error")
    page.fill(f"{form}-reason", "Testing the gallery")
    page.check(f"{form} .setting__confirm input")
    page.click(f"{form} button[type=submit]")
    page.wait_for_selector(f"{form} .setting__saved")


def test_type_to_confirm_dialog(ui_server: Any, open_page: Any, wait_js: Any) -> None:
    page = _open(ui_server, open_page, wait_js).page
    opener = "[data-dialog-open='dlg-demo-purge']"
    page.click(opener)
    page.wait_for_selector("#dlg-demo-purge[open]")
    confirm = "#dlg-demo-purge button[type=submit]"
    assert page.is_disabled(confirm)
    page.fill("#dlg-demo-purge-confirm", "purg")
    assert page.is_disabled(confirm)
    page.fill("#dlg-demo-purge-confirm", "purge")
    assert page.is_enabled(confirm)
    _escape(page, wait_js, "dlg-demo-purge")
    assert page.evaluate(f'document.activeElement.matches("{opener}")')
    page.click(opener)
    page.fill("#dlg-demo-purge-reason", "Gallery test")
    page.fill("#dlg-demo-purge-confirm", "purge")
    page.click(confirm)
    page.wait_for_selector("#toasts .toast:has-text('nothing changed')")
    assert page.evaluate("!document.getElementById('dlg-demo-purge').open")


def test_live_tail_streams_pauses_and_resumes_after_last_event_id(ui_server: Any, open_page: Any, wait_js: Any) -> None:
    page = _open(ui_server, open_page, wait_js).page
    tail = "#gallery-tail"
    wait_js(page, f"document.querySelectorAll('{tail} .tail__row:not([hidden])').length >= 5")
    # The demo stream closes after 20 events; the client reconnects and resumes after the last id it saw.
    wait_js(
        page,
        "fetch('/admin/_gallery/stats').then(r => r.json())"
        ".then(s => s.last_event_ids.some(id => /^\\d+$/.test(id || '')))",
        15,
    )
    page.click(f"{tail} [data-tail-pause]")
    assert page.get_attribute(f"{tail} [data-tail-pause]", "aria-pressed") == "true"
    assert page.text_content(f"{tail} [data-tail-state]") == "Paused"
    page.wait_for_timeout(1200)
    assert "waiting" in page.text_content(f"{tail} [data-tail-count]")
    page.click(f"{tail} [data-tail-pause]")
    assert "waiting" not in page.text_content(f"{tail} [data-tail-count]")
    page.focus(f"{tail} [data-tail-viewport]")
    page.keyboard.press("ArrowDown")
    assert page.evaluate("document.activeElement.classList.contains('tail__row')")
    page.keyboard.press("Enter")
    page.wait_for_selector("#drawer[open] .kv")
    assert "Request id" in page.text_content("#drawer-body")


def test_chart_legend_zoom_tooltip_and_data_table(ui_server: Any, open_page: Any, wait_js: Any) -> None:
    page = _open(ui_server, open_page, wait_js).page
    chart = "#chart-traffic"
    legend = f"{chart} .legend-item >> nth=0"
    page.click(legend)
    assert page.get_attribute(legend, "aria-pressed") == "false"
    page.click(legend)
    assert page.get_attribute(legend, "aria-pressed") == "true"
    page.click(f"{chart} [data-chart-zoom='in']")
    assert page.get_attribute(f"{chart} [data-chart-zoom='reset']", "aria-pressed") == "true"
    page.click(f"{chart} [data-chart-zoom='reset']")
    assert page.get_attribute(f"{chart} [data-chart-zoom='reset']", "aria-pressed") == "false"
    page.locator(f"{chart} .u-over").scroll_into_view_if_needed()
    box = page.locator(f"{chart} .u-over").bounding_box()
    assert box is not None
    page.mouse.move(box["x"] + box["width"] / 2, box["y"] + box["height"] / 2)
    page.wait_for_selector(f"{chart} .chart__tip:not([hidden])")
    assert page.locator(f"{chart} .chart__tip-row").count() >= 2
    page.click(f"{chart} .chart__table > summary")
    assert page.locator(f"{chart} .chart__table tbody tr").count() == 144
    label = page.get_attribute(f"{chart} [data-chart-plot]", "aria-label") or ""
    assert label.startswith("Requests in and upstream calls")


def test_heatmap_shows_numbers_on_request(ui_server: Any, open_page: Any, wait_js: Any) -> None:
    page = _open(ui_server, open_page, wait_js).page
    button = "#heat-week [data-heatmap-numbers]"
    width = "document.querySelectorAll('#heat-week .heat__value')[5].getBoundingClientRect().width"
    assert page.evaluate(width) <= 1  # visually hidden, still read by screen readers
    page.click(button)
    assert page.get_attribute(button, "aria-pressed") == "true"
    assert page.evaluate(width) > 4
    assert page.locator("#heat-week tbody th[scope=row]").count() == 7


# ------------------------------------------------------------------------------------------- screenshots


def test_screenshots_for_review(ui_server: Any, open_page: Any, wait_js: Any, tmp_path: Path) -> None:
    """Full-page screenshots in both themes at both sizes; into docs/screenshots/ when ROXY_SCREENSHOTS=1."""
    out = REPO / "docs" / "screenshots" if os.environ.get("ROXY_SCREENSHOTS") == "1" else tmp_path
    out.mkdir(parents=True, exist_ok=True)
    for theme in ("dark", "light"):
        for name, size in (("1440", DESKTOP), ("390", PHONE)):
            page = _open(ui_server, open_page, wait_js, theme=theme, size=size).page
            page.wait_for_timeout(1200)  # let the live tail fill in
            path = out / f"gallery-{theme}-{name}.png"
            page.screenshot(path=str(path), full_page=True, animations="disabled")
            assert path.stat().st_size > 10_000
