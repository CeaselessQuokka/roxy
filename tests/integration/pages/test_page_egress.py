"""The Egress page (`/admin/egress`, plan 14.1 and 8.5): integration tests against the real app.

What this is
    Tests with data written by the real services (`pages_app.seed_traffic()`: traffic through the proxy): the page
    and every card fragment answer 200 for an admin and redirect otherwise, every registry card and every inline
    setting of the `egress#*` anchors is there, the numbers equal the admin API's (usage, the budget tiles, the
    top endpoints table), the rotator URL and the exit addresses are never shown whole, hostile caller text stays
    inert, the forms post to the API routes with CSRF (the provider figure is audited, the URL replace and the
    re-enable need a fresh second factor), no filter or range ever fails the page, and an empty database says why
    each part is empty.

Why it exists
    The P11 contract: every page proves its guards, its parity with the API (plan P6), its output encoding (plan
    9.16), that no secret reaches the HTML (plan 9.8: the rotator URL), and its empty states.

What to read next
    `roxy/admin/pages/egress.py`, `tests/e2e/test_page_egress.py`.
"""

from __future__ import annotations

from typing import Any

import pytest

from roxy.admin.pages import registry
from roxy.admin.pages.testing import HOSTILE, parse_html
from roxy.core.reasons import Egress
from roxy.core.style_guard import find_style_issues
from roxy.egress.guard import LeakTrip

PAGE = "/admin/egress"
PAGE_ID = "egress"


def _cards() -> list[registry.CardSpec]:
    return list(registry.cards_for(PAGE_ID))


async def _all_html(page: Any) -> list[tuple[str, str]]:
    out = [("page", (await page.get(PAGE)).text)]
    for card in _cards():
        out.append((card.id, (await page.fragment(PAGE_ID, card.id)).text))
    return out


async def test_the_page_and_its_fragments_need_a_signed_in_admin(anon: Any) -> None:
    for path in [PAGE, *(f"{PAGE}/fragment/{card.id}" for card in _cards())]:
        response = await anon.get(path)
        assert response.status_code == 302, path
        assert response.headers["location"] == "/admin"


async def test_every_card_renders_without_an_error_and_holds_its_settings(page: Any, pages_app: Any) -> None:
    await pages_app.seed_traffic()
    doc = await page.doc(PAGE)
    for card in _cards():
        assert doc.select_one(f"section#{card.id}[data-card]") is not None, card.id
        fragment = await page.doc(f"{PAGE}/fragment/{card.id}")
        section = fragment.select_one(f"section#{card.id}[data-card]")
        assert section is not None, card.id
        assert fragment.select_one("[data-card-error]") is None, (card.id, section.text()[:300])
        for spec in registry.settings_for(registry.anchor(PAGE_ID, card.id)):
            assert section.select_one(f'[data-setting-key="{spec.key}"]') is not None, (card.id, spec.key)
    assert not doc.select("[data-card-error]")
    assert doc.select_one('link[href*="css/pages/egress"]') is not None
    assert doc.select_one('script[type="module"][src*="js/pages/egress"]') is not None
    deferred = {node.get("id") for node in doc.select("section.page-card--lazy[hx-trigger=load]")}
    assert deferred == {"rotator", "exit-ips", "sessions"}
    assert find_style_issues((await page.get(PAGE)).text, "egress") == []


# ============================================================================================ secrets and caller text


async def test_the_rotator_url_and_full_exit_addresses_never_reach_the_page(
    page: Any, pages_app: Any, fake_secrets: dict[str, str]
) -> None:
    pool = pages_app.ctx.egress.rotator
    now = int(pages_app.clock.now())
    pool._recent.append({"ip": "203.0.113.77", "at": now, "source": "probe", "session_id": "s" * 16})
    url = fake_secrets["rotator_url"]
    password = url.split(":", 2)[2].split("@", 1)[0]
    for where, html in await _all_html(page):
        assert url not in html, where
        assert password not in html, where
        assert "fakeuser" not in html, where
        assert "203.0.113.77" not in html, where
        assert "s" * 16 not in html, where
    rotator = await page.doc(f"{PAGE}/fragment/rotator")
    assert "http://127.0.0.1:9" in rotator.text()  # the masked form: scheme, host and port
    exits = await page.doc(f"{PAGE}/fragment/exit-ips")
    assert "203.0.113.0/24" in exits.text()
    reveal = exits.select_one('[data-action="exit-ips-reveal"]')
    assert reveal is not None
    assert reveal.get("data-reveal-url") == "/admin/api/v1/egress/exit-ips?reveal=true"
    before = (await page.api("GET", "audit", params={"action": "egress.exit_ips_reveal"})).json()["total"]
    revealed = (await page.api("GET", "egress/exit-ips", params={"reveal": "true"})).json()
    assert revealed["items"][0]["ip"] == "203.0.113.77"
    after = (await page.api("GET", "audit", params={"action": "egress.exit_ips_reveal"})).json()["total"]
    assert after == before + 1


async def test_hostile_endpoint_text_is_inert(page: Any, pages_app: Any, inert: Any) -> None:
    await pages_app.seed_traffic()
    for where, html in await _all_html(page):
        inert(html, f"egress {where}")
    top = await page.get(PAGE, params={"egress": "direct", "q": HOSTILE["img"]})
    inert(top.text, "egress top endpoints search")
    assert "&lt;img src=x onerror=alert(1)&gt;" in top.text  # the search box shows it back, as text


# ============================================================================================ one source of truth


async def test_the_numbers_equal_the_api(page: Any, pages_app: Any) -> None:
    await pages_app.seed_traffic()
    usage = (await page.api("GET", "egress/usage")).json()
    doc = await page.doc(f"{PAGE}/fragment/usage")
    for item in usage["items"]:
        tile = doc.select_one(f'article[data-egress="{item["egress"]}"]')
        assert tile is not None
        assert f"Calls {item['calls']:,}" in tile.text()
    assert next(i for i in usage["items"] if i["egress"] == "direct")["calls"] > 0
    budget = (await page.api("GET", "egress/rotator/budget")).json()
    budget_doc = await page.doc(f"{PAGE}/fragment/budget")
    for tile in budget["tiles"]:
        assert budget_doc.select_one(f'[data-kpi="{tile["key"]}"]') is not None, tile["key"]
    assert budget["projection"]["sentence"] in budget_doc.text()
    top = (await page.api("GET", "egress/top-endpoints", params={"egress": "direct"})).json()
    top_doc = await page.doc(PAGE, params={"egress": "direct"})
    rows = top_doc.select('#top-endpoints [data-table="egress_top_endpoints"] tbody tr[data-row-id]')
    assert len(rows) == len(top["items"])
    assert top["total"] > 0
    trips = (await page.api("GET", "egress/trips")).json()
    assert trips["items"] == []
    assert "The leak guard has not stopped anything" in (await page.doc(f"{PAGE}/fragment/trips")).text()


@pytest.mark.parametrize(
    ("path", "params"),
    [
        (PAGE, {"egress": "bogus"}),
        (PAGE, {"page": "abc", "page_size": "7", "sort": "nope", "order": "x"}),
        (PAGE, {"q": "x" * 600}),
        (PAGE, {"range": "custom", "from": "2026-01-02", "to": "2026-01-01"}),
        (PAGE, {"range": "1y", "granularity": "minute"}),
        (f"{PAGE}/fragment/sessions", {"range": "all"}),
        (f"{PAGE}/fragment/top-endpoints", {"egress": "credential", "page": "9999999"}),
    ],
    ids=lambda value: value if isinstance(value, str) else "-".join(value),
)
async def test_no_filter_or_range_ever_fails_the_page(
    page: Any, pages_app: Any, path: str, params: dict[str, str]
) -> None:
    await pages_app.seed_traffic()
    response = await page.get(path, params=params, htmx=path != PAGE)
    assert response.status_code == 200, (path, params, response.text[:300])
    assert "data-card-error" not in response.text, (path, params)


# ============================================================================================ actions go to the API


async def test_the_provider_figure_is_recorded_through_the_api_and_shown(page: Any) -> None:
    doc = await page.doc(f"{PAGE}/fragment/budget")
    form = doc.select_one('form[data-api-url="/admin/api/v1/egress/provider-report"]')
    assert form is not None
    assert form.select_one('input[name="reported_gb"][data-json="float"]') is not None
    refused = await page.api("POST", "egress/provider-report", json={"reported_gb": 1.5}, csrf=False)
    assert refused.status_code == 403
    done = await page.api("POST", "egress/provider-report", json={"reported_gb": 1.5, "reason": HOSTILE["img"]})
    assert done.status_code == 201, done.text
    after = await page.doc(f"{PAGE}/fragment/budget")
    assert "1.50 GB" in after.text()


async def test_the_url_replace_needs_a_fresh_factor_and_never_echoes_the_url(page: Any, pages_app: Any) -> None:
    doc = await page.doc(f"{PAGE}/fragment/rotator")
    form = doc.select_one("#dlg-rotator-url form[data-api-form]")
    assert form is not None
    assert form.get("data-api-url") == "/admin/api/v1/rotator/url"
    assert form.get("data-api-method") == "PUT"
    assert form.select_one('input[name="url"][type="password"]') is not None
    new_url = "http://otheruser:otherpass@127.0.0.2:8000"
    page.make_mfa_stale()
    stale = await page.api("PUT", "rotator/url", json={"url": new_url, "reason": "page test"})
    assert stale.status_code == 403
    assert stale.json()["error"]["code"] == "reauth_required"
    await page.fresh_mfa()
    done = await page.api("PUT", "rotator/url", json={"url": new_url, "reason": "page test"})
    assert done.status_code == 200, done.text
    after = await page.get(f"{PAGE}/fragment/rotator", htmx=True)
    assert "otherpass" not in after.text
    assert "otheruser" not in after.text
    assert "http://127.0.0.2:8000" in after.text
    revert = parse_html(after.text).select_one("#dlg-rotator-revert form[data-api-form]")
    assert revert is not None
    assert revert.get("data-api-method") == "DELETE"


async def test_a_leak_guard_trip_is_shown_with_its_re_enable_form(page: Any, pages_app: Any, inert: Any) -> None:
    egress = pages_app.ctx.egress
    await egress._on_leak(LeakTrip(Egress.DIRECT, "header " + HOSTILE["img"], "caller", "01J9ZZZZZZZZZZZZZZZZZZZZZZ"))
    html = (await page.fragment(PAGE_ID, "trips")).text
    inert(html, "egress trips")
    doc = parse_html(html)
    assert "Direct is disabled by the leak guard" in doc.text()
    form = doc.select_one('form[data-api-url="/admin/api/v1/egress/direct/enable"]')
    assert form is not None
    assert form.select_one('textarea[name="reason"][required]') is not None
    page.make_mfa_stale()
    stale = await page.api("POST", "egress/direct/enable", json={"reason": "fixed"})
    assert stale.status_code == 403
    await page.fresh_mfa()
    enabled = await page.api("POST", "egress/direct/enable", json={"reason": "fixed"})
    assert enabled.status_code == 200, enabled.text
    assert "has not stopped anything" in (await page.doc(f"{PAGE}/fragment/trips")).text()


async def test_an_empty_database_explains_itself(page: Any) -> None:
    top = (await page.doc(f"{PAGE}/fragment/top-endpoints")).text()
    assert "No rotator bytes in this range" in top
    exits = (await page.doc(f"{PAGE}/fragment/exit-ips")).text()
    assert "No exit addresses recorded yet" in exits
    sessions = (await page.doc(f"{PAGE}/fragment/sessions")).text()
    assert "No rotator calls in this range" in sessions
    budget = (await page.doc(f"{PAGE}/fragment/budget")).text()
    assert "No rotator bytes yet this cycle" in budget
