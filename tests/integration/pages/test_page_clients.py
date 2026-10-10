"""The Clients page (`/admin/clients`, plan 14.1 Clients row; v1 Callers and Top Talkers, rows 73 and 92): integration.

What this is
    Tests against the real app with traffic sent through the real proxy (`pages_app.seed_traffic()`: several
    addresses and places, a throttled client, probes, a hostile `Roblox-Id`, User-Agents and paths): the page, every
    fragment, the client drawer and the client's own page answer 200 for an admin and redirect otherwise; every
    registry card and every catalog setting of its anchors is there; the tables equal the clients API's for the same
    range and search; hostile text stays inert; a forged place id gets no drawer and no actions; the actions post to
    the clients API with CSRF (refused without it) and a ban shows in the view; the lookup form posts to the API; and
    no filter, range or bad value fails the page.

Why it exists
    Plan P11 page rules: one source of truth per number (P6), security (9.2, 9.6, 9.16), help (14.7), settings next
    to their feature (15.6) and v1 parity (C3).

What to read next
    `roxy/admin/pages/clients.py`, `tests/e2e/test_page_clients.py`.
"""

from __future__ import annotations

from typing import Any

import pytest

from roxy.admin.pages import registry
from roxy.admin.pages.testing import HOSTILE, PLACES, parse_html
from roxy.core.style_guard import find_style_issues

PAGE = "/admin/clients"
IP = "192.0.2.41"


async def test_the_page_its_fragments_and_views_need_a_signed_in_admin(anon: Any) -> None:
    paths = [PAGE, *(f"{PAGE}/fragment/{card.id}" for card in registry.cards_for("clients"))]
    paths += [f"{PAGE}/client?kind=ip&key={IP}", f"{PAGE}/ip/{IP}", f"{PAGE}/place/{PLACES[0]}"]
    for path in paths:
        response = await anon.get(path)
        assert response.status_code == 302, path
        assert response.headers["location"] == "/admin"


async def test_every_card_fragment_and_inline_setting_is_there(page: Any, pages_app: Any) -> None:
    await pages_app.seed_traffic()
    doc = await page.doc(PAGE)
    assert len(doc.select("h1")) == 1
    for card in registry.cards_for("clients"):
        assert doc.select_one(f"section#{card.id}[data-card]") is not None, card.id
        fragment = await page.doc(f"{PAGE}/fragment/{card.id}")
        assert fragment.select_one(f"section#{card.id}[data-card]") is not None, card.id
        assert fragment.select_one("[data-card-error]") is None, card.id
        for spec in registry.settings_for(registry.anchor("clients", card.id)):
            assert fragment.select_one(f'[data-setting-key="{spec.key}"]') is not None, (card.id, spec.key)
    assert doc.select_one('#places [data-table="client_places"]') is not None
    assert doc.select_one("section#ips.page-card--lazy") is not None
    ips = await page.doc(f"{PAGE}/fragment/ips")
    assert ips.select_one('[data-table="client_ips"]') is not None
    assert doc.select_one('#lookup form[data-api-url="/admin/api/v1/clients/lookup"]') is not None
    assert doc.select_one('link[href*="css/pages/clients"]') is not None
    assert doc.select_one('script[type="module"][src*="js/pages/clients"]') is not None


async def test_the_tables_equal_the_clients_api(page: Any, pages_app: Any) -> None:
    await pages_app.seed_traffic()
    for kind, card in (("places", "places"), ("ips", "ips")):
        for params in ({}, {"sort": "last_seen", "order": "asc"}, {"q": "203.0"}, {"range": "1h"}):
            api = (await page.api("GET", f"clients/{kind}", params=params)).json()
            doc = await page.doc(f"{PAGE}/fragment/{card}", params=params)
            count = doc.select_one(".dt__count").text()
            if api["total"]:
                assert f"of {api['total']:,}" in count, (kind, params, count)
            else:
                assert count == "No rows", (kind, params)
            shown = [row.select_one('td[data-col="key"]').text() for row in doc.select("tbody tr[data-row-id]")]
            assert len(shown) == len(api["items"]), (kind, params)
    main = await page.doc(PAGE, params={"q": PLACES[0]})
    assert main.select_one('#places input[name="q"]').get("value") == PLACES[0]


async def test_hostile_text_is_inert_and_a_forged_place_gets_no_actions(page: Any, pages_app: Any, inert: Any) -> None:
    await pages_app.seed_traffic()
    response = await page.get(PAGE)
    inert(response.text, "clients page")
    assert "&lt;script&gt;alert(&#39;roxy&#39;)&lt;/script&gt;" in response.text
    assert find_style_issues(response.text, "clients page") == []
    for card in registry.cards_for("clients"):
        fragment = await page.fragment("clients", card.id)
        inert(fragment.text, f"clients {card.id}")
        assert find_style_issues(fragment.text, f"clients {card.id}") == [], card.id
    doc = parse_html(response.text)
    for row in doc.select("#places tbody tr[data-row-id]"):
        key = row.select_one('td[data-col="key"]').text()
        if "<script>" in key:
            assert row.get("data-drawer-src") is None
            assert "forged header" in key
    forged = await page.get(f"{PAGE}/client", params={"kind": "place", "key": HOSTILE["script"]})
    assert forged.status_code == 200
    inert(forged.text, "forged place")
    assert "not a number" in forged.text
    assert "data-api-url" not in forged.text
    assert (await page.get(f"{PAGE}/place/abc")).status_code == 404
    assert (await page.get(f"{PAGE}/ip/not-an-ip")).status_code == 404
    for ip in ("203.0.113.50", "203.0.113.51", "2001:db8::7"):
        view = await page.get(f"{PAGE}/client", params={"kind": "ip", "key": ip})
        assert view.status_code == 200
        inert(view.text, f"client {ip}")
        assert find_style_issues(view.text, f"client {ip}") == []
    own = await page.get(f"{PAGE}/ip/203.0.113.50")
    assert own.status_code == 200
    inert(own.text, "client page")


async def test_the_client_view_shows_the_api_numbers_and_its_actions(page: Any, pages_app: Any) -> None:
    await pages_app.seed_traffic()
    api = (await page.api("GET", f"clients/ips/{IP}")).json()
    view = parse_html((await page.get(f"{PAGE}/client", params={"kind": "ip", "key": IP})).text)
    root = view.select_one("[data-client-view]")
    assert root.get("data-client-kind") == "ip"
    assert root.get("data-client-src").startswith("/admin/clients/client?")
    facts = view.select_one(".client-view__facts").text()
    assert f"Requests {api['totals']['requests']:,}" in facts
    for name in ("ban", "bypass", "rule"):
        form = view.select_one(f"dialog#dlg-client-{name} form[data-api-form]")
        assert form.get("data-api-url") == f"/admin/api/v1/clients/ips/{IP}/{name}", name
    reset = view.select_one("dialog#dlg-client-reset form[data-api-form]")
    assert reset.get("data-api-url") == "/admin/api/v1/data/resets"
    assert reset.select_one('input[name="client"]').get("value") == IP
    assert view.select_one("[data-chart][data-series]") is not None
    assert "Recent probes" in view.text()
    place = parse_html((await page.get(f"{PAGE}/client", params={"kind": "place", "key": PLACES[0]})).text)
    assert place.select_one(f'form[data-api-url="/admin/api/v1/clients/places/{PLACES[0]}/lookup"]') is not None
    rule = place.select_one("dialog#dlg-client-rule form[data-api-form]")
    assert rule.get("data-api-url") == f"/admin/api/v1/clients/places/{PLACES[0]}/rule"
    page_doc = await page.doc(f"{PAGE}/place/{PLACES[0]}")
    assert page_doc.select_one("h1").text() == f"Place {PLACES[0]}"
    assert page_doc.select_one("[data-client-view]") is not None


async def test_actions_need_csrf_and_a_ban_shows_in_the_view_and_the_table(page: Any, pages_app: Any) -> None:
    await pages_app.seed_traffic()
    refused = await page.api("POST", f"clients/ips/{IP}/ban", json={"minutes": 60}, csrf=False)
    assert refused.status_code == 403
    done = await page.api("POST", f"clients/ips/{IP}/ban", json={"minutes": 60, "reason": "test " + HOSTILE["img"]})
    assert done.status_code == 200, done.text
    view = await page.get(f"{PAGE}/client", params={"kind": "ip", "key": IP})
    assert "Banned until" in view.text
    table = parse_html((await page.fragment("clients", "ips", q=IP)).text)
    assert table.select_one('td[data-col="banned"]').text() == "banned"
    bypass = await page.api("POST", f"clients/ips/{IP}/bypass", json={"expires_in_h": 1})
    assert bypass.status_code == 200, bypass.text
    view = await page.get(f"{PAGE}/client", params={"kind": "ip", "key": IP})
    assert "Bypasses the limits" in view.text
    lookup = await page.api("POST", "clients/lookup", json={"id": PLACES[0], "kind": "place"})
    assert lookup.status_code == 200, lookup.text
    assert lookup.json()["result"]["name"] == HOSTILE["img"]
    places = await page.fragment("clients", "places", q=PLACES[0])
    assert "&lt;img src=x onerror=alert(1)&gt;" in places.text


async def test_clear_activity_is_a_previewed_family_reset(page: Any, pages_app: Any) -> None:
    await pages_app.seed_traffic()
    doc = parse_html((await page.fragment("clients", "activity")).text)
    form = doc.select_one("dialog#dlg-clients-reset-activity form[data-api-form]")
    assert form.get("data-expected") == "reset activity"
    digest = form.select_one('input[name="preview"]').get("value")
    preview = await page.api("POST", "data/resets/preview", json={"scope": "family", "families": ["activity"]})
    assert preview.json()["preview"] == digest
    view = parse_html((await page.get(f"{PAGE}/client", params={"kind": "ip", "key": IP})).text)
    client_digest = view.select_one('dialog#dlg-client-reset input[name="preview"]').get("value")
    body = {"scope": "client", "client_type": "ip", "client": IP}
    assert (await page.api("POST", "data/resets/preview", json=body)).json()["preview"] == client_digest
    run = await page.api("POST", "data/resets", json={**body, "preview": client_digest, "reason": "test"})
    assert run.status_code in (200, 202), run.text


@pytest.mark.parametrize(
    "params",
    [
        {"page": "abc"},
        {"page": "0"},
        {"page_size": "7"},
        {"sort": "bogus"},
        {"sort": "bot_score"},
        {"order": "sideways"},
        {"q": "x" * 500},
        {"range": "forever"},
        {"range": "custom", "from": "yesterday"},
        {"page": "99999999"},
        {"lookup": "<b>"},
    ],
    ids=lambda p: "-".join(p),
)
async def test_no_filter_or_range_ever_fails_the_page(page: Any, pages_app: Any, params: dict[str, str]) -> None:
    await pages_app.seed_traffic()
    for path in (PAGE, *(f"{PAGE}/fragment/{card.id}" for card in registry.cards_for("clients"))):
        response = await page.get(path, params=params)
        assert response.status_code == 200, (path, params, response.text[:300])
        assert "data-card-error" not in response.text, (path, params)
    for kind, key in (("ip", IP), ("place", PLACES[0]), ("ip", "::1"), ("nope", "x"), ("ip", "")):
        response = await page.get(f"{PAGE}/client", params={**params, "kind": kind, "key": key})
        assert response.status_code == 200, (kind, key, params)


async def test_an_empty_database_explains_itself(page: Any) -> None:
    for card_id, text in (("places", "No places in this range"), ("ips", "No addresses in this range")):
        response = await page.fragment("clients", card_id)
        assert response.status_code == 200
        assert text in response.text
    view = await page.get(f"{PAGE}/client", params={"kind": "ip", "key": IP})
    assert view.status_code == 200
    assert "None in this range" in view.text
