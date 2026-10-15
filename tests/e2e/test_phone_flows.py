"""The three phone flows of plan 14.8 in a real browser: pause the proxy, apply a recommendation, run a health check.

What this is
    Browser tests against the real app (`dashboard`, tests/e2e/conftest.py) on a phone: a 390 by 844 viewport with
    touch (a coarse pointer, so the touch layout of layout.css applies), in the dark and the light theme. Plan 14.8
    says the owner must be able to pause the proxy, see recommendations and run a health check from a phone; each
    flow here does that end to end, starting from the Overview, the way a thumb would:
      * pause: the top bar's Pause button, the dialog with a message for callers, the paused dashboard (and a proxy
        request that really gets the 503 with that message), then Resume the same way;
      * apply a recommendation: from the Overview's top recommendations or from the bottom bar's Advice item (the
        phone's bell, with the open count), the drawer, the dry-run preview, Apply with a reason, then Undo;
      * run a health check: from the bottom bar's Health item or the Overview's Check Proxy Health button, and the
        live run view filling in over the event stream until the run finishes.
    Every tap goes through `Phone.tap`, which first checks that the target is at least 44 by 44 px (a touch target,
    plan 14.8 and WCAG 2.5.5) and then taps it with the touchscreen. After every step (`Phone.step`): no sideways
    scroll, axe-core finds nothing serious or critical, and no console error, page error or Content Security Policy
    violation so far; a viewport screenshot of the step is saved to `.remake/p11_reports/shots/` for the visual
    review, and with `ROXY_SCREENSHOTS=1` the dark theme's to `docs/screenshots/phone_<flow>_<step>.png` (as
    tests/e2e/test_docs_screenshots.py does, so an ordinary run leaves the repository alone; the second entry of a
    flow adds only its own first step there). At the end of each flow no CSP report reached the server either
    (`GET /security/csp-reports`). As in test_docs_screenshots.py, `ROXY_SCREENSHOTS=1` also runs the flows on the
    dashboard seeded with ordinary text (`clean_dashboard`) and writes the documentation copies as palette PNGs
    (`pages_harness.save_compact_screenshot`); an ordinary run keeps the hostile seed.

Why it exists
    The page tests check each page at phone width; only a flow shows that the controls a phone needs are reachable,
    big enough, not hidden behind the bottom bar, and that the dialogs, drawers and the live run view work with
    touch. These are the three things the owner asked to do from a phone.

How it works
    `phone` builds a fresh browser context per flow (touch, mobile viewport, the admin's session cookie, the theme
    saved as the admin's preference, as `open_admin` does) and records CSP violations from the first byte. The
    shared seeded recommendation stays open for other tests: the recommendation flow makes its own (the harness's
    `seed_recommendation`), with the rule that would resolve it switched off while it runs. Every state change is put
    back in a `finally` (pause, settings). Every wait is bounded.

What to read next
    tests/e2e/conftest.py, templates/admin/_layout/{topbar,mobile_nav,control_dialogs}.html, static/css/layout.css
    (the phone and touch rules), tests/e2e/test_page_recommendations.py and tests/e2e/test_page_health.py.
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable, Collection, Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from pages_harness import (
    SESSION_COOKIE_NAME,
    THEMES,
    VIEWPORTS,
    hostile_text_in,
    save_compact_screenshot,
    seed_recommendation,
)

REPO = Path(__file__).resolve().parents[2]
DOCS_SHOTS = REPO / "docs" / "screenshots"
REVIEW_SHOTS = REPO / ".remake" / "p11_reports" / "shots"
WRITE_DOCS = os.environ.get("ROXY_SCREENSHOTS") == "1"
"""Write the documentation copies (the dark theme's steps) only when asked, as test_docs_screenshots.py does."""

if WRITE_DOCS:

    @pytest.fixture(scope="module")
    def dashboard(clean_dashboard: Any) -> Any:
        """The documentation pictures come from the dashboard seeded with ordinary text (tests/e2e/conftest.py);
        without `ROXY_SCREENSHOTS=1` this override does not exist and the module uses the shared hostile seed."""
        return clean_dashboard


WIDTH, HEIGHT = VIEWPORTS["phone"]
TOUCH_PX = 44
"""Plan 14.8: every control reachable with a touch target of at least 44 by 44 px."""
RUN_TIMEOUT_S = 150
"""A whole health run (every check, 4 at a time, each with its own timeout); the harness refuses outside calls."""
QUIET_RULE = "insight_up_429_endpoint_enabled"
PAUSE_MESSAGE = "Back soon, paused from a phone"

# Records Content Security Policy violations from the moment the document starts (as tests/e2e/conftest.py does).
CSP_RECORDER = """
window.__csp = [];
document.addEventListener("securitypolicyviolation", (e) => {
  window.__csp.push({directive: e.violatedDirective, blocked: e.blockedURI, source: e.sourceFile,
                     line: e.lineNumber, disposition: e.disposition});
});
"""
SETTLED = """() => !document.querySelector(
  '.htmx-request, .htmx-swapping, .htmx-settling, .htmx-added, [aria-busy="true"].page-card--lazy')"""
ANIMATIONS_DONE = """() => document.getAnimations().every(
  (a) => a.playState !== "running" || a.effect.getComputedTiming().iterations === Infinity)"""
NO_HOSTILE_MARKUP = """() => !document.querySelector('img[src="x"], [onerror], [onclick], a[href^="javascript:"]')
  && typeof window.__pwned === "undefined\""""
IGNORED_CONSOLE = ("favicon.ico",)
RUN_WATCHER = """(() => {
  const start = () => {
    window.__runStates = [];
    const note = () => {
      const run = document.querySelector('#run [data-run-id]');
      if (!run) return;
      const progress = document.querySelector('#run .hl-progress');
      const seen = `${run.dataset.runId}|${run.dataset.runState}|${progress ? progress.textContent.trim() : ""}`;
      if (window.__runStates[window.__runStates.length - 1] !== seen) window.__runStates.push(seen);
    };
    note();
    new MutationObserver(note).observe(document.body, {subtree: true, childList: true, characterData: true,
                                                       attributes: true});
  };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start, {once: true});
  else start();
})();"""
"""Records every state of the Run card from each document's first paint (an init script that only observes: it
changes nothing on the page, and runs outside the page's CSP like the CSP recorder)."""


@dataclass
class Phone:
    """One flow on a phone: a touch browser context signed in as the dashboard admin, and what it reported."""

    page: Any
    theme: str
    flow: str
    base_url: str
    wait_for: Callable[..., Any]
    run_axe: Callable[[Any], list[dict[str, Any]]]
    docs_steps: Collection[str] | None = None
    """The steps whose dark screenshot goes to docs/screenshots (None: every step)."""
    properties: list[tuple[str, object]] | None = None
    """The test's `user_properties` (what `record_property` writes to): each documentation copy's palette stats
    (`--junitxml` shows them)."""
    console: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    taps: list[str] = field(default_factory=list)

    # ---- moving around

    def goto(self, path: str) -> None:
        self.page.goto(self.base_url + path, wait_until="load")
        self.settle()

    def wait(self, expression: str, timeout: float = 10.0) -> Any:
        """Poll a JavaScript expression until it is truthy, then wait until htmx is idle."""
        value = self.wait_for(self.page, expression, timeout)
        self.wait_for(self.page, SETTLED, timeout)
        return value

    def settle(self, timeout: float = 45.0) -> None:
        """Wait until the page's lazy cards have loaded (static/js/cards.js loads them one at a time after the
        page; a placeholder that does not move is scrolled into view, one at a time) and htmx is idle."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not self.page.evaluate("document.querySelectorAll('.page-card--lazy').length"):
                break
            try:
                self.wait_for(self.page, "() => !document.querySelector('.page-card--lazy')", 4.0)
            except AssertionError:
                self.page.evaluate(
                    "() => { const card = document.querySelector('.page-card--lazy:not(.htmx-request)');"
                    " if (card) card.scrollIntoView(); }"
                )
        self.wait_for(self.page, SETTLED, 15.0)
        self.page.evaluate("window.scrollTo(0, 0)")

    # ---- touch

    def target(self, locator: Any, what: str) -> Any:
        """The one visible element `locator` names, checked to be a touch target (at least 44 by 44 px)."""
        locator.wait_for(state="visible", timeout=10_000)
        assert locator.count() == 1, f"{what}: {locator.count()} elements match"
        box = locator.bounding_box()
        assert box is not None, f"{what} has no box"
        size = f"{what} is {box['width']:.0f} by {box['height']:.0f} px on a phone ({self.theme})"
        assert box["width"] >= TOUCH_PX - 0.5, f"{size}; a touch target is at least {TOUCH_PX} px wide"
        assert box["height"] >= TOUCH_PX - 0.5, f"{size}; a touch target is at least {TOUCH_PX} px tall"
        return locator

    def tap(self, locator: Any, what: str) -> None:
        """Tap a control with the touchscreen, after checking it is big enough for a thumb."""
        self.target(locator, what).tap()
        self.taps.append(what)

    def type_into(self, locator: Any, text: str, what: str) -> None:
        """Tap a text field (a touch target too) and type into it."""
        self.tap(locator, what)
        locator.fill(text)

    # ---- checks

    def overflows(self) -> bool:
        """True when the page scrolls sideways: wider than the phone (a mobile browser would also zoom out)."""
        widest = "Math.max(document.documentElement.scrollWidth, document.body.scrollWidth)"
        return bool(self.page.evaluate(f"{widest} > Math.min(window.innerWidth, {WIDTH}) + 1"))

    def problems(self, expected: Sequence[str] = ()) -> list[str]:
        found = [
            line
            for line in self.console
            if line.startswith("error:")
            and not line.endswith(IGNORED_CONSOLE)
            and not any(part in line for part in expected)
        ]
        found += [f"page error: {error}" for error in self.errors]
        found += [f"CSP: {item}" for item in self.page.evaluate("window.__csp || []")]
        return found

    def step(self, name: str, *, expected: Sequence[str] = (), shot_first: bool = False) -> None:
        """One step of the flow: no sideways scroll, axe clean, nothing reported, and a screenshot (taken before
        the checks with `shot_first`, for a screen that changes by itself, such as a run filling in)."""
        where = f"{self.flow} step {name} ({self.theme})"
        if shot_first:
            self.shot(name)
        self.wait_for(self.page, SETTLED, 15.0)
        assert not self.overflows(), f"{where}: the page scrolls sideways on a phone"
        self.wait_for(self.page, ANIMATIONS_DONE)
        found = self.run_axe(self.page)
        assert found == [], f"{where}: axe {found}"
        assert self.page.evaluate(NO_HOSTILE_MARKUP), f"{where}: hostile text became markup"
        problems = self.problems(expected)
        assert not problems, f"{where}: {problems}"
        if not shot_first:
            self.shot(name)

    def shot(self, name: str) -> None:
        """The screen as the phone shows it (the viewport, not the whole page): every step for the review, and the
        dark theme's documentation copy when asked (`ROXY_SCREENSHOTS=1`, a palette PNG: see the module docstring)."""
        REVIEW_SHOTS.mkdir(parents=True, exist_ok=True)
        stem = f"phone_{self.flow}_{name}"
        self.page.screenshot(path=str(REVIEW_SHOTS / f"{stem}_{self.theme}.png"), full_page=False)
        wanted = self.docs_steps is None or name in self.docs_steps
        if WRITE_DOCS and self.theme == "dark" and wanted:
            DOCS_SHOTS.mkdir(parents=True, exist_ok=True)
            shown = hostile_text_in(self.page.locator("body").inner_text())
            assert shown == [], f"{stem}: hostile text {shown} in a documentation picture"
            stats = save_compact_screenshot(self.page, DOCS_SHOTS / f"{stem}.png", full_page=False)
            if self.properties is not None:
                self.properties.append((f"screenshot {stem}", stats))


def csp_reports(dashboard: Any) -> int:
    """CSP reports stored in the last hour (the recorder flushed first, so a report sent a moment ago counts)."""
    dashboard.flush()
    answer = dashboard.api("GET", "security/csp-reports", params={"range": "1h", "page_size": 10})
    assert answer.status_code == 200, answer.text
    return int(answer.json()["total"])


@pytest.fixture
def phone(
    browser: Any, dashboard: Any, wait_js: Any, axe: Any, request: pytest.FixtureRequest
) -> Iterator[Callable[..., Phone]]:
    """`phone(flow, theme, docs_steps=None)`: a fresh touch context at 390 by 844, signed in, the theme saved as the
    admin's own."""
    contexts: list[Any] = []

    def factory(flow: str, theme: str, docs_steps: Collection[str] | None = None) -> Phone:
        answer = dashboard.api("POST", "prefs", json={"theme": theme})
        assert answer.status_code == 200, answer.text
        context = browser.new_context(
            viewport={"width": WIDTH, "height": HEIGHT},
            color_scheme=theme,
            base_url=dashboard.base_url,
            has_touch=True,
            is_mobile=True,
            device_scale_factor=1,
        )
        contexts.append(context)
        # A `__Host-` cookie by host and path, as a sign-in on 127.0.0.1 stores it (see tests/e2e/conftest.py).
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
        page = context.new_page()
        page.set_default_timeout(15_000)
        properties = request.node.user_properties  # what `record_property` appends to, without its xunit2 warning
        record = Phone(page, theme, flow, dashboard.base_url, wait_js, axe, docs_steps, properties)
        page.add_init_script(CSP_RECORDER)
        page.on("console", lambda message: record.console.append(f"{message.type}: {message.text}"))
        page.on("pageerror", lambda error: record.errors.append(str(error)))
        return record

    yield factory
    for context in contexts:
        context.close()


@pytest.fixture
def quiet_rule(dashboard: Any) -> Iterator[None]:
    """The seeded recommendation comes from UP-429-ENDPOINT, which the live engine would resolve (the seeded traffic
    does not prove it): the rule is off while a flow runs, and on again afterwards."""
    dashboard.change_settings({QUIET_RULE: 0})
    try:
        yield
    finally:
        dashboard.change_settings({QUIET_RULE: 1})


@pytest.fixture
def no_scheduled_runs(dashboard: Any) -> Iterator[None]:
    """Scheduled health runs off while a flow runs (one run at a time in the fleet: a scheduled one would take it)."""
    before = dashboard.api("GET", "settings/health_auto_interval_h").json()["setting"]["value"]
    dashboard.change_settings({"health_auto_interval_h": 0})
    try:
        yield
    finally:
        dashboard.change_settings({"health_auto_interval_h": before})


# ============================================================================================ pause and resume


@pytest.mark.parametrize("theme", THEMES)
def test_pause_and_resume_the_proxy_from_a_phone(phone: Any, dashboard: Any, theme: str) -> None:
    reports = csp_reports(dashboard)
    flow = phone("pause", theme)
    page = flow.page
    try:
        flow.goto("/admin/overview")
        flow.step("1_overview")

        flow.tap(page.locator(".topbar__pause"), "the top bar's Pause button")
        flow.wait("document.querySelector('#dlg-pause[open]') !== null")
        flow.step("2_dialog")

        flow.type_into(page.locator("#dlg-pause-message"), PAUSE_MESSAGE, "the message for callers")
        with page.expect_navigation(timeout=15_000):
            flow.tap(page.locator('#dlg-pause .dialog__foot button[type="submit"]'), "the dialog's Pause proxy")
        flow.settle()
        assert dashboard.api("GET", "protection/pause").json()["paused"] is True
        assert "Resume" in page.locator(".topbar__pause").inner_text()
        assert PAUSE_MESSAGE in page.locator("body").inner_text()  # the pause banner says what callers see
        with dashboard.http() as client:  # and callers really get it
            answer = client.get(
                "/games.roblox.com/v1/games?universeIds=8814",
                headers={"X-Forwarded-For": "192.0.2.88", "User-Agent": "Roblox/WinInet"},
            )
        assert answer.status_code == 503, answer.text
        assert PAUSE_MESSAGE in answer.text
        flow.step("3_paused")

        flow.tap(page.locator(".topbar__pause"), "the top bar's Resume button")
        flow.wait("document.querySelector('#dlg-pause[open]') !== null")
        flow.step("4_resume_dialog")

        with page.expect_navigation(timeout=15_000):
            flow.tap(page.locator('#dlg-pause .dialog__foot button[type="submit"]'), "the dialog's Resume proxy")
        flow.settle()
        assert dashboard.api("GET", "protection/pause").json()["paused"] is False
        assert "Pause" in page.locator(".topbar__pause").inner_text()
        flow.step("5_resumed")
    finally:
        dashboard.api("POST", "protection/pause", json={"paused": False})
    assert csp_reports(dashboard) == reports, "a CSP report reached the server during the flow"


# ============================================================================================ a recommendation


def drawer_of(rec_id: str) -> str:
    return f"document.querySelector('#drawer[open] [data-rec-detail=\"{rec_id}\"]') !== null"


@pytest.mark.usefixtures("quiet_rule")
@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("entry", ["overview", "bell"])
def test_apply_a_recommendation_from_a_phone_then_undo_it(phone: Any, dashboard: Any, theme: str, entry: str) -> None:
    reports = csp_reports(dashboard)
    # Hostile text in an ordinary run (the shared seed); ordinary text on the documentation's clean dashboard.
    recommendation = seed_recommendation(dashboard.ctx, dashboard.clock, severity="critical", hostile=dashboard.hostile)
    rec_id: str = dashboard.run(recommendation)
    before = dashboard.api("GET", "settings/cache_ttl_seconds").json()["setting"]["value"]
    # The bell entry adds only its own first step to the documentation (the drawer steps are the same).
    flow = phone("apply", theme) if entry == "overview" else phone("apply_bell", theme, docs_steps={"1_list"})
    page = flow.page
    try:
        flow.goto("/admin/overview")
        if entry == "overview":
            # The Overview's top recommendations (most severe and newest first): the new critical one leads.
            item = page.locator(f'#recommendations li[data-rec="{rec_id}"]')
            item.scroll_into_view_if_needed()
            flow.step("1_overview")
            with page.expect_navigation(timeout=15_000):  # to the Recommendations page, `?rec=` opens the drawer
                flow.tap(item.locator(".ov-rec__title a"), "the recommendation on the Overview")
            assert f"rec={rec_id}" in page.url
            flow.settle()
        else:
            # On a phone the bell is the bottom bar's Advice item, with the open count on it.
            advice = page.locator('.mobile-nav a.mobile-nav__item[href="/admin/recommendations"]')
            assert advice.locator(".count-badge").count() == 1, "the Advice item shows the open count"
            flow.tap(advice, "the bottom bar's Advice item")
            page.wait_for_url("**/admin/recommendations**")
            flow.settle()
            flow.step("1_list")
            flow.tap(page.locator(f'#list tr[data-row-id="rec-{rec_id}"] [data-dt-open]'), "the recommendation's row")
        flow.wait(drawer_of(rec_id), timeout=15)
        flow.step("2_drawer")

        flow.tap(page.locator('#drawer [data-action="recommendation-preview"]'), "Preview")
        flow.wait("document.querySelector('#drawer form.rec-apply') !== null", timeout=30)
        flow.step("3_preview")

        flow.type_into(
            page.locator("#drawer form.rec-apply textarea[name=reason]"), "Applied from a phone", "the reason field"
        )
        flow.tap(page.locator('#drawer [data-action="recommendation-apply"]'), "Apply")
        flow.wait("/Applied/.test(document.querySelector('#toasts').innerText)", timeout=20)
        flow.wait(drawer_of(rec_id) + " && document.querySelector('#drawer [data-action=\"recommendation-undo\"]')")
        assert "Applied" in page.locator("#drawer .rec-detail__lead").inner_text()
        assert dashboard.api("GET", "settings/cache_ttl_seconds").json()["setting"]["value"] == 300
        flow.step("4_applied")

        flow.tap(page.locator('#drawer [data-action="recommendation-undo"]'), "Undo the changes")
        flow.wait("/Undone/.test(document.querySelector('#toasts').innerText)", timeout=20)
        flow.wait(
            drawer_of(rec_id) + " && /Rolled back/.test(document.querySelector('#drawer .rec-detail__lead').innerText)"
        )
        assert dashboard.api("GET", "settings/cache_ttl_seconds").json()["setting"]["value"] == before
        # Newest first by action number: the dashboard runs on the wall clock, which WSL steps back about 0.9 s every
        # 31 s, so the apply and the undo may carry seconds in the wrong order (the default sort is by time).
        history = dashboard.api(
            "GET", "recommendations/history", params={"recommendation": rec_id, "sort": "id", "order": "desc"}
        ).json()
        assert [item["action"] for item in history["items"]] == ["undo", "apply"]
        flow.step("5_undone")
    finally:
        dashboard.change_settings({"cache_ttl_seconds": before})
    assert csp_reports(dashboard) == reports, "a CSP report reached the server during the flow"


# ============================================================================================ a health check


def newest_run(dashboard: Any) -> int:
    return int(dashboard.api("GET", "health/runs/latest").json()["id"])


RUN_IN_VIEW = """(() => { const s = document.querySelector('#run .hl-run');
  return s && s.getBoundingClientRect().top >= 0 && s.getBoundingClientRect().top < window.innerHeight * 0.4; })()"""


def run_newer_than(before: int) -> str:
    return (
        "(() => { const n = document.querySelector('#run [data-run-id]'); "
        f"return n && Number(n.dataset.runId) > {before}; }})()"
    )


@pytest.mark.usefixtures("no_scheduled_runs")
@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("entry", ["bottom_bar", "overview_button"])
def test_run_a_health_check_from_a_phone_and_watch_it_live(phone: Any, dashboard: Any, theme: str, entry: str) -> None:
    reports = csp_reports(dashboard)
    before = newest_run(dashboard)
    if entry == "bottom_bar":
        flow = phone("health", theme)
    else:  # the run view is the same: the documentation gets this entry's own first step only
        flow = phone("health_overview", theme, docs_steps={"1_overview"})
    page = flow.page
    page.add_init_script(RUN_WATCHER)
    flow.goto("/admin/overview")
    if entry == "bottom_bar":
        flow.tap(page.locator('.mobile-nav a.mobile-nav__item[href="/admin/health"]'), "the bottom bar's Health item")
        page.wait_for_url("**/admin/health**")
        flow.settle()
        assert page.locator('#run input[name="include_credential"]').is_checked()
        flow.step("1_health_page")
        flow.tap(page.locator("#run label.hl-start__cred"), "Include the credential check")
        assert not page.locator('#run input[name="include_credential"]').is_checked()
        flow.tap(page.locator('#run [data-action="health-run"]'), "Run a health check")
    else:
        # The Overview header's one-tap button runs every check but the credential's and opens the run.
        flow.step("1_overview")
        with page.expect_navigation(timeout=15_000):
            flow.tap(page.locator('[data-action="overview-health-run"]'), "Check Proxy Health")
    page.wait_for_url("**run=*", timeout=20_000)
    flow.wait_for(page, run_newer_than(before), 20)
    run_id = int(page.locator("#run [data-run-id]").first.get_attribute("data-run-id") or 0)
    assert f"run={run_id}" in page.url
    # The run's section comes into view (below the form on a phone), so the progress is on screen.
    flow.wait_for(page, RUN_IN_VIEW, 10)
    flow.step("2_live_view", shot_first=True)  # the run as it fills in: the screenshot comes first

    flow.wait(
        f'document.querySelector(\'#run [data-run-id="{run_id}"][data-run-state="finished"]\') !== null',
        timeout=RUN_TIMEOUT_S,
    )
    assert page.locator("#run [data-check]").count() > 20
    assert page.locator('#run [data-check-status="pending"]').count() == 0
    assert page.locator('#run [data-check="H-CRED-AUTH"]').get_attribute("data-check-status") == "n/a"
    flow.wait(f"document.querySelector('#history tr[data-row-id=\"run-{run_id}\"]') !== null", timeout=20)
    flow.step("3_finished")
    # The live view: what the Run card showed of this run, in order, from the first paint of the Health page.
    seen = [item.split("|", 2) for item in page.evaluate("window.__runStates || []")]
    states = [(state, progress) for shown, state, progress in seen if shown == str(run_id)]
    assert states, seen
    assert states[-1][0] == "finished", seen
    if entry == "bottom_bar":
        # Started from the Health page, the card switched to the run at once and showed it filling in.
        assert any(state == "running" and "checks done" in progress for state, progress in states), seen
    assert csp_reports(dashboard) == reports, "a CSP report reached the server during the flow"
