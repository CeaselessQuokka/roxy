"""The design system under stress in a real browser: modals, teardown, keyboard safety, errors and session edges.

What this is
    Playwright tests for behaviors the P11 design review found broken, each written so it fails on the code before
    the fix: tooltips, toasts and announcements while a modal dialog is open; focus never hidden under the phone
    bottom bar; an off switch for single-key shortcuts and a guard for unsaved edits; charts and live tails released
    when they leave the page; live tail text filters debounced; the stream's `gap` and `unauthorized` events
    (marked on the tail; every stream stops with no reconnect); the palette following only local links; the CSRF
    token refresh and the re-authentication signal; logout and drawer load errors; the session-expired overlay
    leaving other dialogs alone; Escape on a tooltip inside a dialog; reduced motion; real shadows; and heartbeats
    when the heartbeat interval is longer than the activity window.

Why it exists
    These are the edges a dashboard meets in daily use (a session expiring mid-edit, an htmx swap replacing a chart
    every few seconds, a screen reader user in a dialog), and plan 14.9 (WCAG 2.2 AA), P9 (bounded memory) and 9.6
    (sessions and CSRF) make each one a requirement rather than a nicety.

How it works
    Same fixtures as tests/e2e/test_design_system.py (tests/e2e/conftest.py), against the development gallery.
    Chrome DevTools Protocol sessions read the accessibility tree (is a live region hidden by the open modal?) and
    count canvas objects after a forced garbage collection (is a removed chart really released?). Server answers
    are faked with `page.route`, which never leaves the browser; the one foreign URL is aborted before any
    connection is made (plan 19.12).

What to read next
    static/js/dom.js (the overlay layer and the unsaved-changes check), static/js/dialog.js, static/js/charts.js,
    static/js/live_tail.js, static/js/palette.js, static/js/net.js and static/js/session.js.
"""

from __future__ import annotations

import json
import re
from typing import Any

import pytest

pytestmark = pytest.mark.e2e

GALLERY = "/admin/_gallery"
PHONE = {"width": 390, "height": 844, "is_mobile": True, "has_touch": True}
DESKTOP = {"width": 1440, "height": 900}
ROW_OPENER = "#gallery-endpoints tbody tr:first-child [data-dt-open]"


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
    return page


def _stats(page: Any, ui_server: Any) -> dict[str, Any]:
    result: dict[str, Any] = page.request.get(f"{ui_server.base_url}{GALLERY}/stats").json()
    return result


def _toasts(page: Any) -> list[str]:
    texts: list[str] = page.evaluate("[...document.querySelectorAll('#toasts .toast__text')].map(e => e.textContent)")
    return texts


def _on_top(page: Any, selector: str) -> bool:
    """True when the center of the element is not covered by anything else (it is what a pointer would hit)."""
    covered: bool = page.evaluate(
        """sel => { const node = document.querySelector(sel); if (!node) return false;
             const r = node.getBoundingClientRect();
             const hit = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
             return hit === node || node.contains(hit); }""",
        selector,
    )
    return covered


def _ax_node(page: Any, selector: str) -> dict[str, Any]:
    """The accessibility tree's view of one element: is it ignored, and why (Chrome DevTools Protocol)."""
    cdp = page.context.new_cdp_session(page)
    document = cdp.send("DOM.getDocument", {"depth": 0})
    found = cdp.send("DOM.querySelector", {"nodeId": document["root"]["nodeId"], "selector": selector})
    described = cdp.send("DOM.describeNode", {"nodeId": found["nodeId"]})
    tree = cdp.send(
        "Accessibility.getPartialAXTree",
        {"backendNodeId": described["node"]["backendNodeId"], "fetchRelatives": False},
    )
    first = tree["nodes"][0]
    cdp.detach()
    return {
        "ignored": bool(first.get("ignored")),
        "reasons": [reason.get("name") for reason in first.get("ignoredReasons", [])],
    }


def _live_canvases(page: Any) -> int:
    """Canvas objects still alive in the page's JavaScript heap after a forced garbage collection."""
    cdp = page.context.new_cdp_session(page)
    cdp.send("HeapProfiler.enable")
    cdp.send("HeapProfiler.collectGarbage")
    cdp.send("HeapProfiler.collectGarbage")
    prototype = cdp.send("Runtime.evaluate", {"expression": "HTMLCanvasElement.prototype"})
    objects = cdp.send("Runtime.queryObjects", {"prototypeObjectId": prototype["result"]["objectId"]})
    length = cdp.send(
        "Runtime.callFunctionOn",
        {
            "objectId": objects["objects"]["objectId"],
            "functionDeclaration": "function () { return this.length; }",
            "returnByValue": True,
        },
    )
    cdp.detach()
    return int(length["result"]["value"])


def _inject_buttons(page: Any, container: str) -> None:
    """A help dot and a toast button inside `container` (a dialog body), the way a swapped fragment brings them."""
    page.evaluate(
        """sel => { const box = document.querySelector(sel);
             const help = document.createElement('button'); help.type = 'button'; help.className = 'help-dot';
             help.id = 'probe-help'; help.dataset.help = 'Probe help text'; help.textContent = '?';
             help.setAttribute('aria-label', 'Help: probe');
             const toast = document.createElement('button'); toast.type = 'button'; toast.className = 'btn';
             toast.id = 'probe-toast'; toast.dataset.toast = 'Probe toast'; toast.textContent = 'Toast';
             box.prepend(help, toast); }""",
        container,
    )


# ------------------------------------------------------------------------------------------- overlays and modals


def test_tooltip_toast_and_announcements_work_while_a_modal_is_open(
    ui_server: Any, open_page: Any, wait_js: Any
) -> None:
    page = _open(ui_server, open_page, wait_js)
    page.click(ROW_OPENER)
    page.wait_for_selector("#drawer[open] .kv")
    _inject_buttons(page, "#drawer-body")
    page.focus("#probe-help")
    page.wait_for_selector("#roxy-tip:not([hidden])")
    assert _on_top(page, "#roxy-tip"), "the tooltip is drawn under the open drawer"
    page.click("#probe-toast")
    page.wait_for_selector("#toasts .toast:has-text('Probe toast')")
    assert _on_top(page, "#toasts .toast:last-child"), "the toast is drawn under the open drawer"
    wait_js(page, "document.getElementById('sr-polite').textContent === 'Probe toast'")
    polite = _ax_node(page, "#sr-polite")
    assert not polite["ignored"], polite  # a screen reader inside the modal hears the announcement
    assert _ax_node(page, "#sr-assertive")["reasons"].count("activeModalDialog") == 0
    page.click("#drawer [data-dialog-close]")
    wait_js(page, "!document.getElementById('drawer').open")
    # Back on the page once the modal is gone.
    assert page.evaluate("document.getElementById('toasts').parentElement === document.body")
    assert page.evaluate("document.getElementById('sr-polite').parentElement === document.body")


def test_a_focused_help_dot_keeps_its_tooltip_while_the_page_scrolls(
    ui_server: Any, open_page: Any, wait_js: Any
) -> None:
    """WCAG 1.4.13 (persistent): focus that scrolls the page, or a scroll while focused, must not hide the tip."""
    page = _open(ui_server, open_page, wait_js)
    page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
    page.wait_for_timeout(200)
    page.focus("#g-kpis .help-dot >> nth=0")  # far above: focusing it scrolls the page back up
    page.wait_for_timeout(400)
    assert page.evaluate("!document.getElementById('roxy-tip').hidden"), "the tooltip vanished when focus scrolled"
    page.mouse.wheel(0, 120)
    page.wait_for_timeout(300)
    assert page.evaluate("!document.getElementById('roxy-tip').hidden")
    # Still next to its trigger after the scroll.
    gap = page.evaluate(
        """() => { const t = document.getElementById('roxy-tip').getBoundingClientRect();
             const d = document.activeElement.getBoundingClientRect();
             return Math.min(Math.abs(t.top - d.bottom), Math.abs(d.top - t.bottom)); }"""
    )
    assert gap <= 12


def test_focus_is_never_hidden_under_the_phone_bottom_bar(ui_server: Any, open_page: Any, wait_js: Any) -> None:
    """WCAG 2.4.11 (AA): a focused control is never entirely covered by the fixed bottom bar."""
    page = _open(ui_server, open_page, wait_js, size=PHONE)
    covered = []
    stops = 0
    for _ in range(130):
        page.keyboard.press("Tab")
        info = page.evaluate(
            """() => { const a = document.activeElement; const nav = document.querySelector('.mobile-nav');
                 if (!a || !nav || nav.contains(a) || a.closest('dialog') || a === document.body) return null;
                 const r = a.getBoundingClientRect(); const n = nav.getBoundingClientRect();
                 if (r.width === 0 || r.height === 0 || r.height > n.top) return null;
                 return {hidden: r.top >= n.top - 0.5, el: String(a.id || a.className || a.tagName).slice(0, 60),
                         top: Math.round(r.top), bottom: Math.round(r.bottom), navTop: Math.round(n.top)}; }"""
        )
        if info is None:
            continue
        stops += 1
        if info["hidden"]:
            covered.append(info)
    assert stops > 60
    assert covered == []


# ------------------------------------------------------------------------------------------- keyboard safety


def test_single_key_shortcuts_can_be_turned_off_and_stay_off(ui_server: Any, open_page: Any, wait_js: Any) -> None:
    """WCAG 2.1.4 (A): single-character shortcuts have an off switch; Ctrl+K keeps working."""
    page = _open(ui_server, open_page, wait_js)
    url = page.url
    page.keyboard.press("?")
    page.wait_for_selector("#shortcuts[open]")
    toggle = "#shortcuts [data-shortcuts-toggle]"
    assert page.is_checked(toggle)
    # Focus starts on Close, not on the switch (Space right after "?" must not turn shortcuts off).
    assert page.evaluate("document.activeElement.matches('#shortcuts [data-dialog-close]')")
    page.uncheck(toggle)
    page.click("#shortcuts [data-dialog-close]")
    wait_js(page, "!document.getElementById('shortcuts').open")
    page.click("#main h1")
    for key in ("?", "/", "t", "c"):
        page.keyboard.press(key)
    page.keyboard.press("g")
    page.keyboard.press("s")
    page.wait_for_timeout(400)
    assert page.evaluate("!document.querySelector('dialog[open]')")
    assert page.url == url
    page.keyboard.press("Control+k")  # a modifier shortcut: still on
    page.wait_for_selector("#palette[open]")
    page.keyboard.press("Escape")
    wait_js(page, "!document.getElementById('palette').open")
    page.reload()
    wait_js(page, "document.documentElement.dataset.ready === '1'")
    page.click("#main h1")
    page.keyboard.press("?")
    page.wait_for_timeout(300)
    assert page.evaluate("!document.getElementById('shortcuts').open"), "the off switch was not remembered"
    # The account menu has the same switch.
    page.click(".user-menu > summary")
    assert not page.is_checked(".user-menu [data-shortcuts-toggle]")
    page.check(".user-menu [data-shortcuts-toggle]")
    page.click("#main h1")
    page.keyboard.press("?")
    page.wait_for_selector("#shortcuts[open]")


def test_shortcuts_never_discard_an_unsaved_setting(ui_server: Any, open_page: Any, wait_js: Any) -> None:
    page = _open(ui_server, open_page, wait_js)
    url = page.url
    page.focus("#set-cache_enabled-value")
    page.keyboard.press("Space")  # the switch is now changed but not saved
    page.wait_for_selector("#set-cache_enabled .setting__save", state="visible")
    page.keyboard.press("t")
    page.wait_for_timeout(800)
    assert page.url == url
    assert page.is_visible("#set-cache_enabled .setting__save")
    assert any("not saved" in text for text in _toasts(page)), _toasts(page)
    page.click("#main h1")
    page.keyboard.press("g")
    page.keyboard.press("s")
    page.wait_for_timeout(500)
    assert page.url == url


def test_leaving_the_page_with_an_unsaved_setting_asks_first(ui_server: Any, open_page: Any, wait_js: Any) -> None:
    page = _open(ui_server, open_page, wait_js)
    url = page.url
    seen: list[str] = []

    def on_dialog(dialog: Any) -> None:
        seen.append(dialog.type)
        dialog.dismiss()  # "stay on this page"

    page.on("dialog", on_dialog)
    page.fill("#set-cache_ttl_seconds-value", "15m")
    page.wait_for_selector("#set-cache_ttl_seconds .setting__save", state="visible")
    page.click(".nav-link[data-nav-id='cache']", no_wait_after=True)
    page.wait_for_timeout(800)
    assert seen == ["beforeunload"]
    assert page.url == url
    assert page.input_value("#set-cache_ttl_seconds-value") == "15m"


def test_escape_on_a_tooltip_inside_a_dialog_only_hides_the_tooltip(
    ui_server: Any, open_page: Any, wait_js: Any
) -> None:
    """WCAG 1.4.13: dismissing hover or focus content must not also close the dialog it sits in."""
    page = _open(ui_server, open_page, wait_js)
    page.click("[data-dialog-open='dlg-demo-purge']")
    page.wait_for_selector("#dlg-demo-purge[open]")
    _inject_buttons(page, "#dlg-demo-purge .dialog__body")
    page.focus("#probe-help")
    page.wait_for_selector("#roxy-tip:not([hidden])")
    page.keyboard.press("Escape")
    page.wait_for_timeout(250)
    assert page.evaluate("document.getElementById('roxy-tip').hidden")
    assert page.evaluate("document.getElementById('dlg-demo-purge').open"), "Escape also closed the dialog"
    page.keyboard.press("Escape")
    wait_js(page, "!document.getElementById('dlg-demo-purge').open")


# ------------------------------------------------------------------------------------------- teardown (plan P9)


def test_charts_removed_from_the_page_are_released(ui_server: Any, open_page: Any, wait_js: Any) -> None:
    page = _open(ui_server, open_page, wait_js)
    before = _live_canvases(page)
    page.evaluate(
        """async () => {
             const source = document.getElementById('chart-traffic');
             for (let i = 0; i < 30; i++) {
               const clone = source.cloneNode(true); clone.id = 'probe-chart-' + i; delete clone.dataset.chartReady;
               document.getElementById('main').append(clone);
               document.dispatchEvent(new CustomEvent('htmx:load', {detail: {elt: clone}}));
               await new Promise(r => setTimeout(r, 80));
               clone.remove();
             }
           }"""
    )
    page.wait_for_timeout(500)
    after = _live_canvases(page)
    assert after <= before + 1, f"{after - before} canvases from removed charts are still alive"


def test_charts_swapped_out_by_htmx_are_destroyed(ui_server: Any, open_page: Any, wait_js: Any) -> None:
    page = _open(ui_server, open_page, wait_js)
    before = _live_canvases(page)
    page.evaluate(
        """async () => {
             const source = document.getElementById('chart-latency');
             const host = document.createElement('div'); host.id = 'probe-host';
             document.getElementById('main').append(host);
             for (let i = 0; i < 10; i++) {
               const clone = source.cloneNode(true); clone.id = 'probe-swap-' + i; delete clone.dataset.chartReady;
               host.replaceChildren(clone);
               document.dispatchEvent(new CustomEvent('htmx:load', {detail: {elt: clone}}));
               await new Promise(r => setTimeout(r, 120));
               // What htmx does to old content before a swap removes it.
               clone.dispatchEvent(new CustomEvent('htmx:beforeCleanupElement', {bubbles: true}));
             }
           }"""
    )
    page.wait_for_timeout(300)
    assert page.evaluate("document.querySelectorAll('#probe-host canvas').length") == 0
    assert _live_canvases(page) <= before + 1


def test_a_removed_live_tail_stops_streaming(ui_server: Any, open_page: Any, wait_js: Any) -> None:
    page = _open(ui_server, open_page, wait_js)
    events: list[tuple[str, str]] = []
    page.on("request", lambda r: events.append(("request", r.url)) if "/stream?" in r.url else None)
    page.on("requestfailed", lambda r: events.append(("failed", r.url)) if "/stream?" in r.url else None)
    page.select_option("#gallery-tail select[data-tail-filter='outcome']", "refused")
    for _ in range(60):
        if any(kind == "request" and "outcome=refused" in url for kind, url in events):
            break
        page.wait_for_timeout(50)
    page.wait_for_timeout(400)
    mark = len(events)
    page.evaluate("document.getElementById('gallery-tail').remove()")
    page.wait_for_timeout(1500)
    after = [(kind, url) for kind, url in events[mark:] if "outcome=refused" in url]
    assert ("failed", next(url for kind, url in events if "outcome=refused" in url)) in after, (
        "the removed tail kept its stream open"
    )
    page.wait_for_timeout(1500)
    assert not [url for kind, url in events[mark:] if kind == "request" and "outcome=refused" in url]


def test_live_tail_text_filters_reconnect_once_after_typing(ui_server: Any, open_page: Any, wait_js: Any) -> None:
    page = _open(ui_server, open_page, wait_js)
    urls: list[str] = []
    page.on("request", lambda r: urls.append(r.url) if "/stream" in r.url else None)
    page.click("#gallery-tail-endpoint")
    mark = len(urls)
    page.keyboard.type("games", delay=60)
    assert page.evaluate("document.getElementById('gallery-tail-endpoint').value") == "games"
    page.wait_for_timeout(1000)
    filtered = [url for url in urls[mark:] if "endpoint=" in url]
    assert len(filtered) == 1, filtered
    assert "endpoint=games" in filtered[0]


def test_live_tail_marks_a_gap_and_stops_for_good_on_unauthorized(ui_server: Any, open_page: Any, wait_js: Any) -> None:
    """The server's two control events (roxy/admin/sse.py): `gap` is shown on the tail, `unauthorized` stops every
    stream at once and opens the sign-in overlay, with no reconnect that could only fail."""
    record = open_page(color_scheme="dark", reduced_motion="no-preference", **DESKTOP)
    page = record.page
    live = {"request_id": "r1", "status": 200, "outcome": "served_cache", "endpoint": "games.roblox.com/v1/games"}
    gap = {"after_id": "0", "resumed_to": "1", "position": "1"}
    unauthorized = {"status": 401, "code": "unauthorized", "message": "Session expired"}
    frames = "".join(
        [
            "retry: 200" + "\n\n",
            "event: live" + "\n" + "id: 1" + "\n" + "data: " + json.dumps(live) + "\n\n",
            "event: gap" + "\n" + "id: 2" + "\n" + "data: " + json.dumps(gap) + "\n\n",
            "event: unauthorized" + "\n" + "data: " + json.dumps(unauthorized) + "\n\n",
        ]
    )
    streams: list[str] = []

    def stream(route: Any) -> None:
        streams.append(route.request.url)
        route.fulfill(status=200, headers={"Content-Type": "text/event-stream"}, body=frames)

    page.route(re.compile(r".*/admin/_gallery/stream(\?.*)?$"), stream)
    response = page.goto(f"{ui_server.base_url}{GALLERY}?theme=dark")
    assert response is not None
    assert response.ok
    wait_js(page, "document.documentElement.dataset.ready === '1'")
    page.wait_for_selector("#session-expired[open]")
    wait_js(page, "document.querySelector('#gallery-tail [data-tail-count]').textContent.includes('missed')")
    assert page.text_content("#gallery-tail [data-tail-state]") == "Signed out"
    seen = len(streams)
    page.wait_for_timeout(1500)  # `retry: 200` would have reconnected several times by now
    assert len(streams) == seen, streams


# ------------------------------------------------------------------------------------------- links and requests


def test_palette_follows_only_local_admin_links(ui_server: Any, open_page: Any, wait_js: Any) -> None:
    page = _open(ui_server, open_page, wait_js)
    url = page.url
    foreign: list[str] = []
    page.route("https://example.invalid/**", lambda route: (foreign.append(route.request.url), route.abort()))
    results = [
        {"group": "Settings", "label": "Zzq outside", "hint": "x", "href": "https://example.invalid/x"},
        {"group": "Settings", "label": "Zzq script", "hint": "x", "href": "javascript:void(0)"},
        {"group": "Settings", "label": "Zzq slashes", "hint": "x", "href": "//example.invalid/y"},
    ]
    page.route(
        "**/admin/_gallery/palette?*",
        lambda route: route.fulfill(status=200, content_type="application/json", body=json.dumps(results)),
    )
    page.keyboard.press("Control+k")
    page.wait_for_selector("#palette[open]")
    page.keyboard.type("zzq")
    page.wait_for_timeout(700)
    assert page.locator("#palette-list [data-remote]").count() == 0
    page.keyboard.press("Enter")
    page.wait_for_timeout(500)
    assert foreign == []
    assert page.url == url


@pytest.mark.parametrize(
    ("headers", "body"),
    [
        ({}, json.dumps({"error": {"code": "reauth_required", "message": "Confirm it is you first."}})),
        ({"Roxy-Reauth": "required"}, json.dumps("Re-authentication required")),
    ],
    ids=["json-code", "header"],
)
def test_reauth_required_is_signaled_instead_of_reload_advice(
    ui_server: Any, open_page: Any, wait_js: Any, headers: dict[str, str], body: str
) -> None:
    page = _open(ui_server, open_page, wait_js)
    page.evaluate("window.__reauth = []; document.addEventListener('roxy:reauth', e => window.__reauth.push(e.detail))")
    page.route(
        "**/admin/_gallery/action",
        lambda route: route.fulfill(status=403, content_type="application/json", headers=headers, body=body),
    )
    page.click("#g-server-toast")
    # P11: the "Confirm it is you" dialog takes the signal over (static/js/reauth.js); canceling it says why
    # nothing happened, never "reload".
    page.wait_for_selector("#reauth[open]")
    page.keyboard.press("Escape")
    page.wait_for_selector("#toasts .toast")
    texts = _toasts(page)
    assert not any("Reload" in text for text in texts), texts
    assert any("second factor" in text for text in texts), texts
    assert page.evaluate("window.__reauth.length") == 1
    # A plain CSRF refusal still gets the generic advice.
    page.unroute("**/admin/_gallery/action")
    page.route(
        "**/admin/_gallery/action",
        lambda route: route.fulfill(status=403, content_type="application/json", body=json.dumps("Forbidden")),
    )
    page.click("#g-server-toast")
    page.wait_for_selector("#toasts .toast:has-text('refused')")
    assert page.evaluate("window.__reauth.length") == 1


def test_csrf_token_is_refreshed_by_a_server_event(ui_server: Any, open_page: Any, wait_js: Any) -> None:
    page = _open(ui_server, open_page, wait_js)
    sent: list[str | None] = []
    calls = {"n": 0}

    def handle(route: Any) -> None:
        sent.append(route.request.headers.get("x-csrf-token"))
        calls["n"] += 1
        if calls["n"] == 1:  # the answer to a re-authentication rotates the token
            route.fulfill(status=204, headers={"HX-Trigger": json.dumps({"roxy:csrf": {"token": "fresh-token-1"}})})
        else:
            route.fulfill(status=204)

    page.route("**/admin/_gallery/action", handle)
    page.click("#g-server-toast")
    wait_js(page, "document.querySelector('meta[name=csrf-token]').content === 'fresh-token-1'")
    page.click("#g-server-toast")
    for _ in range(40):
        if len(sent) >= 2:
            break
        page.wait_for_timeout(50)
    assert sent[0] not in (None, "fresh-token-1")
    assert sent[1] == "fresh-token-1"


def test_logout_refused_by_the_server_stays_and_says_so(ui_server: Any, open_page: Any, wait_js: Any) -> None:
    page = _open(ui_server, open_page, wait_js)
    url = page.url
    page.route("**/admin/_gallery/action", lambda route: route.fulfill(status=403, body="Forbidden"))
    page.click(".user-menu > summary")
    page.click(".user-menu__logout button")
    page.wait_for_selector("#toasts .toast:has-text('still signed in')")
    page.wait_for_timeout(500)
    assert page.url == url
    page.unroute("**/admin/_gallery/action")
    if not page.evaluate("document.querySelector('.user-menu').open"):  # the failed attempt left it open
        page.click(".user-menu > summary")
    page.click(".user-menu__logout button")
    page.wait_for_url(re.compile(r".*/admin$"))


def test_a_failed_drawer_load_says_so_in_the_drawer(ui_server: Any, open_page: Any, wait_js: Any) -> None:
    page = _open(ui_server, open_page, wait_js)
    page.route("**/admin/_gallery/drawer?*", lambda route: route.fulfill(status=500, body="boom"))
    page.click(ROW_OPENER)
    page.wait_for_selector("#drawer[open] #drawer-body [role=alert]")
    text = page.inner_text("#drawer-body")
    assert "Loading" not in text
    assert "could not be loaded" in text
    assert not any("Nothing was changed" in toast for toast in _toasts(page))


# ------------------------------------------------------------------------------------------- session edges


def test_session_overlay_keeps_other_dialogs_and_ignores_the_palette(
    ui_server: Any, open_page: Any, wait_js: Any
) -> None:
    page = _open(ui_server, open_page, wait_js)
    url = page.url
    page.click(".topbar__pause")
    page.wait_for_selector("#dlg-pause[open]")
    page.fill("#dlg-pause-message", "half written message")  # P11: the dialog sends the API's `message`
    page.evaluate("document.dispatchEvent(new CustomEvent('roxy:unauthorized', {detail: {source: 'test'}}))")
    page.wait_for_selector("#session-expired[open]")
    assert page.evaluate("document.getElementById('dlg-pause').open"), "the overlay closed the dialog underneath"
    page.keyboard.press("Control+k")
    page.wait_for_timeout(300)
    assert page.evaluate("!document.getElementById('palette').open")
    assert page.evaluate("document.getElementById('session-expired').open")
    page.click("[data-session-stay]")
    assert page.evaluate("!document.getElementById('session-expired').open")
    assert page.evaluate("document.getElementById('dlg-pause').open")
    assert page.input_value("#dlg-pause-message") == "half written message"
    page.wait_for_timeout(1200)
    assert page.url == url


def test_escape_on_the_session_overlay_means_stay(ui_server: Any, open_page: Any, wait_js: Any) -> None:
    page = _open(ui_server, open_page, wait_js)
    page.evaluate("document.dispatchEvent(new CustomEvent('roxy:unauthorized', {detail: {source: 'test'}}))")
    page.wait_for_selector("#session-expired[open]")
    page.keyboard.press("Escape")
    wait_js(page, "!document.getElementById('session-expired').open")
    assert "Staying on this page" in page.text_content("[data-session-countdown]")


def test_heartbeat_reports_activity_when_the_interval_exceeds_the_window(
    ui_server: Any, open_page: Any, wait_js: Any
) -> None:
    """With a 5 s interval and a 2 s window, input is still reported (the tick follows the shorter of the two)."""
    page = _open(ui_server, open_page, wait_js, query="&hb=5&aw=2")
    start = _stats(page, ui_server)["heartbeats"]
    page.mouse.move(400, 300)
    page.mouse.move(420, 320)
    sent = False
    for _ in range(30):
        if _stats(page, ui_server)["heartbeats"] > start:
            sent = True
            break
        page.wait_for_timeout(100)
    assert sent, "input inside the activity window was never reported"


# ------------------------------------------------------------------------------------------- look and motion


def test_spinner_stands_still_with_reduced_motion(ui_server: Any, open_page: Any, wait_js: Any) -> None:
    page = _open(ui_server, open_page, wait_js, reduced_motion="reduce")
    assert page.evaluate("getComputedStyle(document.querySelector('#g-slow-spinner .spinner')).animationName") == "none"


@pytest.mark.parametrize("theme", ["dark", "light"])
def test_popovers_and_cards_have_their_shadows(ui_server: Any, open_page: Any, wait_js: Any, theme: str) -> None:
    page = _open(ui_server, open_page, wait_js, theme=theme)
    page.click(".user-menu > summary")
    assert page.eval_on_selector(".user-menu .menu__panel", "e => getComputedStyle(e).boxShadow") != "none"
    # Cards: a soft shadow in light; transparent (but still a valid value) in dark, where borders carry the edge.
    assert page.eval_on_selector(".card", "e => getComputedStyle(e).boxShadow") != "none"
