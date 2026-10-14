"""Accessibility review of the P11 dashboard pages in a real browser (lens: WCAG 2.2 AA and the phone layout).

What this is
    Reproductions of the accessibility findings of the P11 review (`.remake/p11_review/find_a11y.md`). Each was a
    strict xfail naming its finding (`a11y-<n>: <title>`) until the P11 review round fixed it; each is a regression
    test now (a comment above it names the fix). The refuted a11y-17 (axe `landmark-unique`, a moderate best-practice
    rule outside the plan's serious-and-critical bar) has no test here. axe-core is already clean on every page
    load (tests/e2e), so these tests look at what
    a load does not show: keyboard focus after an update, dialogs opened from menus, the Live tail under focus,
    touch targets with a coarse pointer, the session alert's countdown, errors after a failed save, zoom, reflow and
    text spacing.

Why it exists
    The page tests check each page as it first paints, at 1440x900 and 390x844 with a fine pointer. Keyboard and
    screen reader users, phones with a touch screen, and people who zoom meet the dashboard after it has changed:
    after a sort, a save, a reopened drawer, new rows in the Live tail. Plan 14.8 and 14.9 promise those work too.

How it works
    The fixtures are the browser test fixtures of tests/e2e/conftest.py (`browser`, `open_admin`, `AdminPage`),
    imported here. The dashboard is this module's own seeded `pages_harness.DashboardServer` (module scope, so the
    snooze, the health run and the traffic these tests make never reach another module's pages). `phone_admin`
    opens a page with a touch screen (`has_touch`, `is_mobile`: a coarse pointer, so the touch rules of
    components.css apply) at 390x844.

What to read next
    `.remake/p11_review/find_a11y.md` (the findings), tests/e2e/conftest.py, tests/e2e/test_phone_flows.py,
    static/js/dialog.js, static/js/tables.js, static/js/live_tail.js, static/js/session.js.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from typing import Any

import pytest

import db_threads
from e2e.conftest import AdminPage, browser, open_admin, wait_for_js  # noqa: F401
from pages_harness import DOC_NETS, SESSION_COOKIE_NAME, DashboardServer, PlannedRequest

pytestmark = pytest.mark.e2e

PAGE_IDS = (
    "overview",
    "recommendations",
    "traffic",
    "upstream",
    "egress",
    "cache",
    "endpoints",
    "clients",
    "protection",
    "live",
    "security",
    "health",
    "settings",
    "credential",
    "data",
    "audit",
    "system",
    "help",
)

TOUCH_PX = 44

ACTIVE_JS = """() => { const e = document.activeElement; if (!e || e === document.body) return 'body';
  return e.tagName.toLowerCase() + (e.id ? '#' + e.id : '') + ' "' +
    (e.getAttribute('aria-label') || e.textContent || '').trim().replace(/\\s+/g, ' ').slice(0, 40) + '"'; }"""

FOCUS_SEEN_JS = """(within) => { const e = document.activeElement;
  return Boolean(e && e !== document.body && e.isConnected && e.getClientRects().length
    && (!within || e.closest(within))); }"""


# --------------------------------------------------------------------------------------------- fixtures


@pytest.fixture(scope="module")
def dashboard() -> Iterator[DashboardServer]:
    """This module's own seeded dashboard (the same server tests/e2e uses, but not shared with it)."""
    server = DashboardServer.start(seed=True)
    databases = server.ctx.dbs
    db_threads.share(databases, "tests/review_p11/test_a11y_e2e.py dashboard")
    try:
        yield server
    finally:
        try:
            server.stop()
        finally:
            db_threads.unshare(databases)


@pytest.fixture
def phone_admin(browser: Any, dashboard: DashboardServer) -> Iterator[Callable[..., AdminPage]]:  # noqa: F811
    """`phone_admin(path, theme="light")`: a page on a 390x844 touch screen (coarse pointer), signed in, settled."""
    contexts: list[Any] = []

    def factory(path: str, *, theme: str = "light") -> AdminPage:
        answer = dashboard.api("POST", "prefs", json={"theme": theme})
        assert answer.status_code == 200, answer.text
        assert dashboard.signed_in is not None
        context = browser.new_context(
            viewport={"width": 390, "height": 844},
            color_scheme=theme,
            base_url=dashboard.base_url,
            has_touch=True,
            is_mobile=True,
        )
        contexts.append(context)
        context.add_cookies(
            [
                {
                    "name": SESSION_COOKIE_NAME,
                    "value": dashboard.signed_in.cookie,
                    "domain": "127.0.0.1",
                    "path": "/",
                    "secure": True,
                    "httpOnly": True,
                    "sameSite": "Strict",
                }
            ]
        )
        record = AdminPage(context.new_page(), base_url=dashboard.base_url, theme=theme, width=390)
        record.goto(path)
        return record

    yield factory
    for context in contexts:
        context.close()


def _active(page: Any) -> str:
    return str(page.evaluate(ACTIVE_JS))


def _focus_seen(page: Any, within: str = "") -> bool:
    """True when keyboard focus is on a visible element (not the page body), optionally inside `within`."""
    return bool(page.evaluate(FOCUS_SEEN_JS, within))


def _lum(rgb: tuple[float, float, float]) -> float:
    def channel(value: float) -> float:
        value /= 255
        return value / 12.92 if value <= 0.03928 else ((value + 0.055) / 1.055) ** 2.4

    r, g, b = rgb
    return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)


def _rgb(text: str) -> tuple[float, float, float]:
    inside = text[text.index("(") + 1 : text.index(")")].replace(",", " ").replace("/", " ").split()
    return float(inside[0]), float(inside[1]), float(inside[2])


def _contrast(a: str, b: str) -> float:
    la, lb = sorted((_lum(_rgb(a)), _lum(_rgb(b))), reverse=True)
    return (la + 0.05) / (lb + 0.05)


# ------------------------------------------------------------------------------- a11y-3: touch targets

TOUCH_TARGETS_JS = """(min) => {
  const root = [...document.querySelectorAll('dialog[open]')].pop() || document;
  const out = [];
  const sel = 'a[href], button, input:not([type=hidden]), select, textarea, summary, [role=option]';
  for (const e of root.querySelectorAll(sel)) {
    if (e.disabled || e.closest('[hidden], .sr-only, .skip-link')) continue;
    if (root === document && e.closest('dialog')) continue;
    if (e.closest('details:not([open]) > :not(summary)')) continue;
    if (!e.getClientRects().length) continue;
    const cs = getComputedStyle(e);
    if (cs.visibility === 'hidden') continue;
    let target = e;
    if ((e.type === 'checkbox' || e.type === 'radio') && e.closest('label')) target = e.closest('label');
    const r = target.getBoundingClientRect();
    if (!r.width || !r.height) continue;  // a zero-size link whose ::after is the target (KPI tiles)
    // WCAG's exception for a link inside a sentence: an inline link in a longer block of text.
    const block = e.parentElement ? e.parentElement.closest('p, li, dd, td') : null;
    if (e.tagName === 'A' && cs.display === 'inline' && block
        && block.textContent.trim().length > e.textContent.trim().length + 3) continue;
    if (r.width < min - 0.5 || r.height < min - 0.5) {
      const name = (e.getAttribute('aria-label') || e.textContent || e.value || '').trim().replace(/\\s+/g, ' ');
      const cls = typeof e.className === 'string' && e.className ? '.' + e.className.trim().split(/\\s+/)[0] : '';
      out.push(`${e.getAttribute('role') || e.tagName.toLowerCase()}${cls} "${name.slice(0, 28)}" `
        + `${Math.round(r.width)}x${Math.round(r.height)}`);
    }
  }
  return out;
}"""


@pytest.mark.timeout(900)
# Fixed in the P11 review round (a11y-3, shared fixer): a regression test now.
def test_a11y_3_every_control_is_a_44_px_touch_target_on_a_phone(phone_admin: Callable[..., AdminPage]) -> None:
    """Plan 14.8 and DESIGN 15.3: with a touch screen every control is at least 44 by 44 px. The page tests run the
    phone size with a fine pointer; with a coarse one, every page still has smaller targets (table search boxes,
    rows-per-page selects, `details` summaries, History and Reset links of settings, switches, range sliders, sort
    headers), and so do the palette and the pause dialog (one of the three things the owner must do on a phone)."""
    small: dict[str, list[str]] = {}
    for page_id in PAGE_IDS:
        admin = phone_admin(f"/admin/{page_id}")
        assert admin.page.evaluate("matchMedia('(pointer: coarse)').matches"), "the touch context has a fine pointer"
        found = admin.page.evaluate(TOUCH_TARGETS_JS, TOUCH_PX)
        if found:
            small[page_id] = found
        admin.page.context.close()
    admin = phone_admin("/admin/overview")
    page = admin.page
    # A dialog and the palette open with `roxy-pop` (scale 0.98 to 1): measure them once it has finished, or every
    # 44 px control inside reads 43 px (skeptic fix: the first version measured mid-animation).
    popped = "(sel) => { const d = document.querySelector(sel); return d.open && d.getAnimations().length === 0; }"
    page.tap(".topbar__pause")
    wait_for_js(page, "() => document.querySelector('#dlg-pause').open")
    page.wait_for_function(popped, arg="#dlg-pause", timeout=5000)
    found = page.evaluate(TOUCH_TARGETS_JS, TOUCH_PX)
    if found:
        small["pause dialog"] = found
    page.keyboard.press("Escape")
    wait_for_js(page, "() => !document.querySelector('dialog[open]')")
    page.tap(".search-btn")
    wait_for_js(page, "() => document.querySelector('#palette').open")
    page.wait_for_function(popped, arg="#palette", timeout=5000)
    found = page.evaluate(TOUCH_TARGETS_JS, TOUCH_PX)
    if found:
        small["command palette"] = found
    summary = {where: f"{len(items)} small, for example {items[:4]}" for where, items in small.items()}
    assert not small, f"targets under {TOUCH_PX} px with a touch screen at 390x844: {summary}"


# ------------------------------------------------------------------------------- a11y-1: table updates


# Fixed in the P11 review round (a11y-1, shared fixer): a regression test now.
def test_a11y_1_table_controls_keep_keyboard_focus(open_admin: Callable[..., AdminPage]) -> None:  # noqa: F811
    """Every data table swaps itself (outerHTML) after a sort, a page change or a new page size; the sort buttons,
    the pager and the rows-per-page select have no id htmx could refocus, so keyboard focus falls to the page body
    and the next Tab starts again from the skip link (WCAG 2.4.3). The Audit log stands for every table."""
    admin = open_admin("/admin/audit?page_size=10")
    page = admin.page
    lost: list[str] = []

    def operate(selector: str, key: str, what: str, expect: str) -> None:
        page.evaluate("window.__a11yOld = document.getElementById('audit-log')")
        page.locator(selector).first.focus()
        page.keyboard.press(key)
        admin.wait(
            "() => document.getElementById('audit-log') && document.getElementById('audit-log') !== window.__a11yOld"
        )
        if not page.evaluate("(sel) => Boolean(document.activeElement && document.activeElement.matches(sel))", expect):
            lost.append(f"{what}: focus went to {_active(page)}")

    sort_key = page.locator("#audit-log [data-dt-sort]").nth(1).get_attribute("data-dt-sort")
    operate(
        f'#audit-log [data-dt-sort="{sort_key}"]',
        "Enter",
        f"sort by {sort_key}",
        f'#audit-log [data-dt-sort="{sort_key}"]',
    )
    operate('#audit-log [data-dt-page]:not([disabled])[aria-label="Next page"]', "Enter", "next page", "#audit-log *")
    operate("#audit-log [data-dt-size]", "ArrowDown", "rows per page", "#audit-log *")
    assert not lost, lost


# ------------------------------------------------------------------------------- a11y-4: the Live tail

ROW_LABELS_JS = """() => {
  const focused = document.activeElement && document.activeElement.classList.contains('tail__row')
    ? document.activeElement.getAttribute('aria-label') : null;
  const active = document.querySelector('.tail__row.is-active:not([hidden])');
  return {focused, active: active ? active.getAttribute('aria-label') : null,
          rows: document.querySelectorAll('.tail__row:not([hidden])').length};
}"""


# Fixed in the P11 review round (a11y-4, shared fixer): a regression test now.
def test_a11y_4_the_live_tail_keeps_the_request_under_keyboard_focus(
    open_admin: Callable[..., AdminPage],  # noqa: F811
    dashboard: DashboardServer,
) -> None:
    """Arrow keys move a roving focus over recycled row nodes. When a new request arrives, the tail shifts its
    "active" index but not the DOM focus, so the focused node is refilled with a newer request while the highlight
    moves to another node: a screen reader reads one request, Enter opens another (the active one). Hover pauses the
    tail for a mouse; keyboard focus does not (plan 14.5: "pause on hover ... keyboard navigation")."""
    admin = open_admin("/admin/live")
    page = admin.page
    wait_for_js(page, "() => document.querySelector('[data-live-tail]').dataset.state === 'live'", 20)
    first = [PlannedRequest(f"/users.roblox.com/v1/users/{700 + i}", f"{DOC_NETS[1]}.{70 + i}") for i in range(3)]
    dashboard.send_traffic(first)
    wait_for_js(page, "() => document.querySelectorAll('.tail__row:not([hidden])').length >= 3", 20)
    page.focus("[data-tail-viewport]")
    page.keyboard.press("ArrowDown")
    before = page.evaluate(ROW_LABELS_JS)
    assert before["focused"], f"no row took focus: {before}"
    assert before["focused"] == before["active"], before
    more = [PlannedRequest(f"/users.roblox.com/v1/users/{800 + i}", f"{DOC_NETS[1]}.{80 + i}") for i in range(2)]
    dashboard.send_traffic(more)
    page.wait_for_timeout(3000)  # the stream tails metrics.db every 500 ms; give it a few rounds
    after = page.evaluate(ROW_LABELS_JS)
    assert after["focused"] == before["focused"], f"the focused row now reads {after['focused']!r}, was {before}"
    assert after["active"] == after["focused"], (
        f"Enter would open {after['active']!r}, focus reads {after['focused']!r}"
    )


# ------------------------------------------------------------------------------- a11y-5: session alert


# Fixed in the P11 review round (a11y-5, shared fixer): a regression test now.
def test_a11y_5_the_session_alert_gives_at_least_20_seconds(open_admin: Callable[..., AdminPage]) -> None:  # noqa: F811
    """A session that ended elsewhere (signed out, revoked, idle) shows the alert on the next request and goes to
    the login page after 5 s unless "Stay on this page" is pressed. WCAG 2.2.1 asks for at least 20 seconds to act;
    5 s is less than a screen reader needs to read the alert, and leaving drops the unsaved edit the alert says can
    still be copied (`leaveOnPurpose` turns the "Leave site?" guard off). Here: an edited setting, then the session
    cookie is gone (as after a sign-out elsewhere) and Review gets a 401."""
    admin = open_admin("/admin/settings?key=cache_ttl_seconds")
    page = admin.page
    url = page.url
    form = "form[data-setting-key='cache_ttl_seconds']"
    page.locator(f"{form} [data-setting-input]").first.fill("123")
    page.context.clear_cookies()
    page.locator(f"{form} button[type=submit]").first.click()
    wait_for_js(page, "() => document.querySelector('#session-expired').open", 15)
    page.wait_for_timeout(7000)
    assert page.url == url, f"7 s after the alert the page went to {page.url}"


# ------------------------------------------------------------------------------- a11y-9: failed save

FAILED_SAVE_JS = """(sel) => {
  const f = document.querySelector(sel);
  const err = f.querySelector('.setting__error');
  const value = f.querySelector('[data-setting-input]');
  const confirm = f.querySelector('input[name=confirm_high_risk]');
  const ids = (node) => (node.getAttribute('aria-describedby') || '').split(/\\s+/);
  return {message: err && !err.hidden ? err.textContent.trim() : '', errorId: err ? err.id : '',
          valueInvalid: value.getAttribute('aria-invalid'), confirmInvalid: confirm.getAttribute('aria-invalid'),
          confirmDescribed: ids(confirm).includes(err.id)};
}"""


# Fixed in the P11 review round (a11y-9, shared fixer): a regression test now.
def test_a11y_9_a_refused_high_risk_save_points_at_the_missing_confirmation(
    open_admin: Callable[..., AdminPage],  # noqa: F811
) -> None:
    """A high-risk value saved without ticking "I understand the risk" is refused (422 `confirmation_required`). The
    control shows the API's text "confirm it with confirm_high_risk" (a JSON field name nobody sees on the page),
    sets aria-invalid on the value (which is valid) and leaves the checkbox that is missing neither invalid nor
    described by the message (WCAG 3.3.1, 3.3.3; plan 14.9 "error messages tied by aria-describedby")."""
    admin = open_admin("/admin/settings?key=rotator_hard_stop_pct")
    page = admin.page
    form = "form[data-setting-key='rotator_hard_stop_pct']"
    page.locator(f"{form} [data-setting-input]").first.fill("0")  # 0 is a high-risk value of this setting
    submit = page.locator(f"{form} button[type=submit]").first
    submit.click()
    wait_for_js(page, f"() => document.querySelector(\"{form} [data-setting-submit-label]\").textContent === 'Save'")
    submit.click()
    wait_for_js(page, f'() => !document.querySelector("{form} .setting__error").hidden')
    state = page.evaluate(FAILED_SAVE_JS, form)
    assert "confirm_high_risk" not in state["message"], state
    assert state["confirmInvalid"] == "true", state
    assert state["confirmDescribed"], state
    assert state["valueInvalid"] != "true", state


# ------------------------------------------------------------------------------- a11y-6: menus


@pytest.mark.timeout(400)
# Fixed in the P11 review round (a11y-6, shared fixer): a regression test now.
def test_a11y_6_a_dialog_opened_from_a_menu_returns_focus_to_the_menu(
    open_admin: Callable[..., AdminPage],  # noqa: F811
) -> None:
    """dialog.js closes every open menu before showModal() and remembers the menu item as the opener; the item is
    hidden inside the closed <details>, so on close neither the script nor the browser can focus it and focus falls
    to <body> (WCAG 2.4.3). The account menu (Keyboard shortcuts, Preferences) and Protection > Bans "Delete bans"
    are the menus that open dialogs."""
    lost: list[str] = []

    def through_menu(admin: AdminPage, menu: str, item: str, dialog_id: str) -> None:
        page = admin.page
        page.locator(f"{menu} > summary").first.focus()
        page.keyboard.press("Enter")
        wait_for_js(page, f"() => document.querySelector({json.dumps(menu)}).open")
        page.locator(item).first.focus()
        page.keyboard.press("Enter")
        wait_for_js(page, f"() => document.getElementById({json.dumps(dialog_id)}).open")
        page.keyboard.press("Escape")
        wait_for_js(page, "() => !document.querySelector('dialog[open]')")
        if not _focus_seen(page, menu):
            lost.append(f"{item}: focus went to {_active(page)}")

    overview = open_admin("/admin/overview")
    through_menu(overview, "details.user-menu", ".user-menu .menu__item[data-shortcuts-open]", "shortcuts")
    through_menu(overview, "details.user-menu", ".user-menu .menu__item[data-dialog-open='preferences']", "preferences")
    protection = open_admin("/admin/protection")
    bans_menu = "#bans details.menu:has([data-dialog-open='dlg-prot-bans-expired'])"
    through_menu(protection, bans_menu, "#bans [data-dialog-open='dlg-prot-bans-expired']", "dlg-prot-bans-expired")
    assert not lost, lost


# ------------------------------------------------------------------------------- a11y-7: reopened drawers


# Fixed in the P11 review round (a11y-7, shared fixer): a regression test now.
def test_a11y_7_closing_a_reopened_recommendation_drawer_keeps_focus_on_the_page(
    open_admin: Callable[..., AdminPage],  # noqa: F811
) -> None:
    """An action in the recommendation drawer (snooze, dismiss, undo, apply) closes the drawer, refreshes the list
    (the row that opened it is replaced) and reopens the drawer with `document.body` as its opener; Escape then
    drops focus on <body> (WCAG 2.4.3). The client drawer's actions (static/js/pages/clients.js) do the same."""
    admin = open_admin("/admin/recommendations")
    page = admin.page
    page.locator("#recommendations-list [data-dt-open]").first.focus()
    page.keyboard.press("Enter")
    wait_for_js(
        page, "() => document.querySelector('#drawer').open && document.querySelector('#drawer-body [data-rec-detail]')"
    )
    page.locator("#drawer [data-action^='recommendation-snooze']").first.focus()
    page.keyboard.press("Enter")
    wait_for_js(page, "() => [...document.querySelectorAll('.toast')].some((t) => t.textContent.includes('Snoozed'))")
    page.wait_for_timeout(1200)  # the drawer reopens 350 ms after the success
    wait_for_js(
        page, "() => document.querySelector('#drawer').open && document.querySelector('#drawer-body [data-rec-detail]')"
    )
    page.keyboard.press("Escape")
    wait_for_js(page, "() => !document.querySelector('#drawer').open")
    assert _focus_seen(page, "main"), f"after closing the drawer focus is on {_active(page)}"


# ------------------------------------------------------------------------------- a11y-8: busy buttons


@pytest.mark.timeout(400)
# Fixed in the P11 review round (a11y-8, shared fixer): a regression test now.
def test_a11y_8_busy_buttons_keep_keyboard_focus(open_admin: Callable[..., AdminPage]) -> None:  # noqa: F811
    """Egress "Verify rotation now" and Health "Run a health check" set `disabled` on the focused button while their
    request runs; Chromium moves focus off a disabled element to <body>, and the button never gets it back (the
    Health card is then redrawn too). A keyboard user who pressed the button starts again from the top."""
    lost: list[str] = []
    egress = open_admin("/admin/egress")
    page = egress.page
    page.locator("[data-probe-url]").first.focus()
    page.keyboard.press("Enter")
    wait_for_js(page, "() => document.querySelector('.toast')", 15)
    wait_for_js(page, "() => !document.querySelector('[data-probe-url]').disabled", 15)
    if not page.evaluate("() => document.activeElement === document.querySelector('[data-probe-url]')"):
        lost.append(f"Verify rotation now: focus went to {_active(page)}")

    health = open_admin("/admin/health")
    page = health.page
    before = page.evaluate("() => (document.querySelector('#run [data-run-id]') || {dataset: {}}).dataset.runId || ''")
    box = page.locator("form[data-health-start] [name=include_credential]")
    if box.count() and box.get_attribute("type") == "checkbox":
        box.uncheck()  # the credential check needs a fresh second factor; the rest does not
    page.locator("form[data-health-start] button[type=submit]").first.focus()
    page.keyboard.press("Enter")
    wait_for_js(
        page,
        "() => { const n = document.querySelector('#run [data-run-id]');"
        f" return n && n.dataset.runId !== '{before}'; }}",
        30,
    )
    health.wait("() => true")
    if not _focus_seen(page, "#run"):
        lost.append(f"Run a health check: focus went to {_active(page)}")
    assert not lost, lost


# ------------------------------------------------------------------------------- a11y-10: color-only link

LINK_JS = """() => {
  const a = [...document.querySelectorAll('main a[href]')].find((x) => x.textContent.trim() === 'How the score works');
  if (!a) return null;
  const cs = getComputedStyle(a), ps = getComputedStyle(a.parentElement);
  return {underline: cs.textDecorationLine.includes('underline') || cs.borderBottomStyle !== 'none',
          color: cs.color, around: ps.color};
}"""


@pytest.mark.timeout(400)
# Fixed in the P11 review round (a11y-10, shared fixer): a regression test now.
def test_a11y_10_the_client_page_link_is_not_told_apart_by_hue_alone(
    open_admin: Callable[..., AdminPage],  # noqa: F811
) -> None:
    """`/admin/clients/ip/<ip>` (no page test opens it) ends the bot score sentence with "How the score works", a
    link without an underline whose color is 1.01:1 (dark) and 1.04:1 (light) against the muted sentence around it;
    axe reports `link-in-text-block` (serious) in the light theme (WCAG 1.4.1)."""
    problems: list[str] = []
    for theme in ("light", "dark"):
        admin = open_admin(f"/admin/clients/ip/{DOC_NETS[1]}.99", theme=theme)
        link = admin.page.evaluate(LINK_JS)
        assert link is not None, "the bot score paragraph has no 'How the score works' link"
        ratio = _contrast(link["color"], link["around"])
        if not link["underline"] and ratio < 3:
            problems.append(f"{theme}: no underline and {ratio:.2f}:1 against the sentence")
        serious = [v for v in admin.axe() if v["id"] == "link-in-text-block"]
        if serious:
            problems.append(f"{theme}: axe {serious}")
    assert not problems, problems


# ------------------------------------------------------------------------------- a11y-11: zoom


# Fixed in the P11 review round (a11y-11, shared fixer): a regression test now.
def test_a11y_11_no_page_scrolls_sideways_at_200_percent_zoom(open_admin: Callable[..., AdminPage]) -> None:  # noqa: F811
    """A 1440 to 1800 px screen at 200 percent zoom is a 720 to 900 CSS px window: the layout between the phone and
    the desktop one. Upstream's Buckets card ("Rate overrides") is 809 px wide in a 720 px window and 881 in 800;
    the Live tail's column header row ends at 1,001 px in 800 and 900 px windows (WCAG 1.4.4, 1.4.10)."""
    wide: list[str] = []
    for path, widths in (("/admin/upstream", (720, 800)), ("/admin/live", (800, 900))):
        admin = open_admin(path, width=widths[0], height=450)
        for width in widths:
            admin.page.set_viewport_size({"width": width, "height": 450})
            admin.page.wait_for_timeout(300)
            scroll = admin.page.evaluate("document.documentElement.scrollWidth")
            if scroll > width + 1:
                wide.append(f"{path} at {width} px is {scroll} px wide")
    assert not wide, wide


# ------------------------------------------------------------------------------- a11y-13: the palette

PALETTE_JS = """() => {
  const active = document.querySelector('#palette [role=option][aria-selected=true]');
  const other = [...document.querySelectorAll('#palette [role=option]')].find((o) => !o.hidden && o !== active);
  const list = document.querySelector('#palette');
  const a = getComputedStyle(active), o = getComputedStyle(other), d = getComputedStyle(list);
  const input = getComputedStyle(document.querySelector('#palette-input'));
  const box = getComputedStyle(document.querySelector('#palette .palette__search'));
  const ring = (s) => (s.outlineStyle !== 'none' && parseFloat(s.outlineWidth) > 0)
    || (s.boxShadow && s.boxShadow !== 'none');
  return {activeBg: a.backgroundColor, otherBg: o.backgroundColor, dialogBg: d.backgroundColor,
          activeRing: ring(a) || parseFloat(a.borderLeftWidth) >= 2, inputRing: ring(input) || ring(box),
          placeholder: getComputedStyle(document.querySelector('#palette-input'), '::placeholder').color,
          focused: document.activeElement && document.activeElement.id};
}"""


def _opaque(color: str, under: str) -> str:
    """A `transparent` background shows what is under it."""
    return under if "rgba(0, 0, 0, 0)" in color or color == "transparent" else color


@pytest.mark.timeout(400)
# Fixed in the P11 review round (a11y-13, shared fixer): a regression test now.
def test_a11y_13_the_palette_shows_where_the_keyboard_is(open_admin: Callable[..., AdminPage]) -> None:  # noqa: F811
    """The command palette keeps focus in its input (`outline: none`, nothing on its box) and marks the active option
    (aria-activedescendant) with `--accent-soft` only: 1.18:1 (light) and 1.2:1 (dark) against the other options,
    plus a label color 2.0 to 2.7:1 from the normal text. WCAG 2.4.7 and 1.4.11 ask for a visible mark of at least
    3:1. Its placeholder keeps the browser's gray (no `::placeholder` rule, unlike `.input`): 3.96:1 on the dark
    palette (WCAG 1.4.3 asks 4.5:1; axe does not measure placeholders)."""
    problems: list[str] = []
    for theme in ("light", "dark"):
        admin = open_admin("/admin/overview", theme=theme)
        page = admin.page
        page.keyboard.press("Control+k")
        wait_for_js(page, "() => document.querySelector('#palette').open")
        page.keyboard.press("ArrowDown")
        state = page.evaluate(PALETTE_JS)
        active = _opaque(state["activeBg"], state["dialogBg"])
        other = _opaque(state["otherBg"], state["dialogBg"])
        ratio = _contrast(active, other)
        if not state["activeRing"] and ratio < 3:
            problems.append(f"{theme}: active option {ratio:.2f}:1 against the others, no outline")
        if not state["inputRing"]:
            problems.append(f"{theme}: the focused input ({state['focused']}) has no focus ring")
        placeholder = _contrast(state["placeholder"], state["dialogBg"])
        if placeholder < 4.5:
            problems.append(f"{theme}: the placeholder is {placeholder:.2f}:1 on the palette")
    assert not problems, problems


# ------------------------------------------------------------------------------- a11y-15: reflow


@pytest.mark.timeout(400)
# Fixed in the P11 review round (a11y-15, shared fixer): a regression test now.
def test_a11y_15_pages_reflow_at_320_css_px(open_admin: Callable[..., AdminPage]) -> None:  # noqa: F811
    """WCAG 1.4.10 (AA): content reflows at 320 CSS px (1280 px at 400 percent). Overview (the outcomes table),
    Security (an admin-access badge), Credential (the high-risk list of a setting), Data (the export list) and Help
    scroll sideways by 15 to 59 px."""
    wide: list[str] = []
    for page_id in ("overview", "security", "credential", "data", "help"):
        admin = open_admin(f"/admin/{page_id}", width=320, height=640)
        scroll = admin.page.evaluate("document.documentElement.scrollWidth")
        if scroll > 321:
            wide.append(f"{page_id}: {scroll} px")
    assert not wide, wide


# ------------------------------------------------------------------------------- a11y-14: text spacing

SPACING_CSS = """* { line-height: 1.5 !important; letter-spacing: 0.12em !important; word-spacing: 0.16em !important; }
p { margin-bottom: 2em !important; }"""

APPLY_SPACING_JS = """(css) => { const sheet = new CSSStyleSheet(); sheet.replaceSync(css);
  document.adoptedStyleSheets = [...document.adoptedStyleSheets, sheet]; }"""

CUT_TEXT_JS = """() => [...document.querySelectorAll('.kpi__label, .nav-link__label')]
  .filter((e) => e.getClientRects().length && getComputedStyle(e).position !== 'absolute'
    && (e.scrollHeight > e.clientHeight + 1 || e.scrollWidth > e.clientWidth + 1))
  .map((e) => e.textContent.trim())"""


@pytest.mark.timeout(400)
# Fixed in the P11 review round (a11y-14, shared fixer): a regression test now.
def test_a11y_14_text_spacing_and_size_lose_no_text(open_admin: Callable[..., AdminPage]) -> None:  # noqa: F811
    """WCAG 1.4.12: with line height 1.5, letter spacing 0.12em, word spacing 0.16em and paragraph spacing 2em no
    text is lost. KPI labels are clamped to two lines (`-webkit-line-clamp: 2`), so "Avoided upstream calls
    (percent)" loses its last line, and the sidebar's "Recommendations" ends in an ellipsis; a 200 percent root font
    size cuts the same labels.

    Skeptic narrowing: the first version also failed on the account menu's position at a 200 percent root font size
    and on sideways scrolling at 390 px with the spacing. Neither is lost text (1.4.4 is met by page zoom, and a
    sideways scroll keeps the content reachable), so they no longer decide this test; the review evidence keeps
    them as observations."""
    lost: list[str] = []
    for page_id in ("overview", "cache"):
        admin = open_admin(f"/admin/{page_id}")
        admin.page.evaluate(APPLY_SPACING_JS, SPACING_CSS)
        admin.page.wait_for_timeout(300)
        cut = admin.page.evaluate(CUT_TEXT_JS)
        if cut:
            lost.append(f"{page_id} at 1440 with text spacing: cut {cut}")
    admin = open_admin("/admin/overview")
    admin.page.evaluate("document.documentElement.style.fontSize = '200%'")
    admin.page.wait_for_timeout(300)
    cut = admin.page.evaluate(CUT_TEXT_JS)
    if cut:
        lost.append(f"overview at 200 percent text: cut {cut}")
    assert not lost, lost


# ------------------------------------------------------------------------------- a11y-16: live regions

CHATTER_JS = """() => { window.__a11yTalk = [];
  for (const region of document.querySelectorAll('[data-live-tail] [role=status], [data-live-tail] [aria-live]')) {
    new MutationObserver(() => window.__a11yTalk.push(region.textContent.trim()))
      .observe(region, {childList: true, characterData: true, subtree: true});
  } }"""


# Fixed in the P11 review round (a11y-16, shared fixer): a regression test now.
def test_a11y_16_the_live_tail_does_not_announce_pointer_passes(open_admin: Callable[..., AdminPage]) -> None:  # noqa: F811
    """The tail's state label is a `role=status` live region, and the hover pause writes "Paused while the pointer is
    over the list" into it, then "Live" again: every pass of the mouse over the list is two announcements (plan
    14.9: live regions throttled so screen readers are not flooded)."""
    admin = open_admin("/admin/live")
    page = admin.page
    wait_for_js(page, "() => document.querySelector('[data-live-tail]').dataset.state === 'live'", 20)
    page.evaluate(CHATTER_JS)
    box = page.locator("[data-tail-viewport]").bounding_box()
    assert box is not None
    for _ in range(3):
        page.mouse.move(box["x"] + 30, box["y"] + 30)
        page.wait_for_timeout(150)
        page.mouse.move(2, box["y"] + box["height"] + 200)
        page.wait_for_timeout(150)
    talk = page.evaluate("window.__a11yTalk")
    assert not talk, f"{len(talk)} live region updates from three pointer passes: {talk}"


# ------------------------------------------------------------------------------- a11y-2: the range picker


# Fixed in the P11 review round (a11y-2, shared fixer): a regression test now.
def test_a11y_2_arrow_keys_move_through_the_time_ranges_without_leaving_the_page(
    open_admin: Callable[..., AdminPage],  # noqa: F811
) -> None:
    """The top bar's range picker submits on every `change` of its radios (static/js/app.js `initRangeForm`), and an
    arrow key in a radio group both moves and checks: the first ArrowRight from "24 hours" loads the page again with
    `range=7d`, so a keyboard user can never reach "90 days" or "All" without one page load per step (WCAG 3.2.2 On
    Input, Level A; the comparison radios do the same)."""
    admin = open_admin("/admin/overview")
    page = admin.page
    page.evaluate("window.__a11yStay = 1")
    page.locator(".range > summary").first.focus()
    page.keyboard.press("Enter")
    wait_for_js(page, "() => document.querySelector('details.range').open")
    page.locator(".range input[name=range]:checked").first.focus()
    before = page.evaluate("document.activeElement.value")
    page.keyboard.press("ArrowRight")
    page.wait_for_timeout(2000)
    page.wait_for_load_state("load")
    stayed = page.evaluate("window.__a11yStay === 1")
    assert stayed, f"one ArrowRight from the {before} range loaded {page.url}"


# ------------------------------------------------------------------------------- a11y-19: errors on a phone


@pytest.mark.timeout(400)
# Fixed in the P11 review round (a11y-19, shared fixer): a regression test now.
def test_a11y_19_an_error_never_makes_a_phone_dialog_scroll_sideways(
    open_admin: Callable[..., AdminPage],  # noqa: F811
) -> None:
    """The API's message for a bad address quotes the value ("'999...' is not a valid IP"), and `.field__error` does
    not break long words, so at 390 px the error box of Protection > Bypass ("Add a bypass") and Lists ("Deny an
    address") runs to 546 px and the dialog scrolls sideways by 174 px (the lens: no sideways scroll after showing
    an error; WCAG 1.4.10). The value is refused, so nothing changes."""
    admin = open_admin("/admin/protection", width=390, height=844, theme="light")
    page = admin.page
    wide: list[str] = []
    for dialog_id in ("dlg-prot-bypass-add", "dlg-prot-deny-add"):
        page.evaluate(f"document.querySelector('[data-dialog-open={dialog_id}]').click()")
        wait_for_js(page, f"() => document.getElementById('{dialog_id}').open")
        page.locator(f"#{dialog_id} [name=cidr]").fill("9" * 120 + "." + "8" * 100)
        page.locator(f"#{dialog_id} button[type=submit]").click()
        wait_for_js(page, f"() => document.querySelector('#{dialog_id} .field__error:not([hidden])')", 15)
        extra = page.evaluate(
            f"(() => {{ const d = document.getElementById('{dialog_id}'); return d.scrollWidth - d.clientWidth; }})()"
        )
        if extra > 1:
            wide.append(f"{dialog_id} scrolls sideways by {extra} px")
        page.keyboard.press("Escape")
        wait_for_js(page, "() => !document.querySelector('dialog[open]')")
    assert not wide, wide
