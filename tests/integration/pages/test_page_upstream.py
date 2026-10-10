"""The Upstream page (`/admin/upstream`, plan 14.1 and 7.12): integration tests against the real app.

What this is
    Tests with data written by the real services (`pages_app.seed_traffic()`: traffic through the proxy, a Roblox
    429 and a Roblox 503 included, hostile paths and User-Agents): the page and every card fragment answer 200 for an
    admin and redirect otherwise, every registry card and every inline setting of the `upstream#*` anchors is there,
    the numbers equal the admin API's for the same range and filters, hostile caller text stays inert in the cards,
    the drawers and the testers, the forms post to the API routes with CSRF (and the reset needs a reason), a
    bucket key with slashes and braces reaches the override API as one path segment, the trace explains a real
    request, no filter or range ever fails the page, and an empty database says why each part is empty.

Why it exists
    The P11 contract: every page proves its guards, its parity with the API (one source of truth, plan P6), its
    output encoding (plan 9.16) and its empty states.

What to read next
    `roxy/admin/pages/upstream.py`, `tests/e2e/test_page_upstream.py` (the same page in a browser).
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote

import pytest

from roxy.admin.pages import registry
from roxy.admin.pages.testing import HOSTILE, parse_html
from roxy.core.style_guard import find_style_issues

PAGE = "/admin/upstream"
PAGE_ID = "upstream"
EXTRA_ROUTES = (
    "/admin/upstream/bucket?key=global",
    "/admin/upstream/routing-rule?id=1",
    "/admin/upstream/routing-test?target=x",
)
TEMPLATE_KEY = "endpoint:games.roblox.com/v1/games/{universeId}/votes"


def _cards() -> list[registry.CardSpec]:
    return list(registry.cards_for(PAGE_ID))


def _count(doc: Any) -> str:
    node = doc.select_one(".dt__count")
    assert node is not None
    return str(node.text())


async def _too_many(pages_app: Any) -> str:
    """One request through the proxy that Roblox answers 429; returns its Roxy-Request-Id."""
    client = pages_app.harness.new_client()
    response = await client.get(
        "/thumbnails.roblox.com/v1/too-many?size=60x60",
        headers={"User-Agent": "Roblox/WinInet", "X-Forwarded-For": "198.51.100.77"},
    )
    await pages_app.flush()
    return str(response.headers["Roxy-Request-Id"])


# ============================================================================================ guards and structure


async def test_the_page_its_fragments_and_partials_need_a_signed_in_admin(anon: Any) -> None:
    paths = [PAGE, *(f"{PAGE}/fragment/{card.id}" for card in _cards()), *EXTRA_ROUTES]
    for path in paths:
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
        assert section.select_one(".page-card--lazy") is None
        assert "page-card--lazy" not in section.classes()
        for spec in registry.settings_for(registry.anchor(PAGE_ID, card.id)):
            assert section.select_one(f'[data-setting-key="{spec.key}"]') is not None, (card.id, spec.key)
    assert not doc.select("[data-card-error]")
    assert doc.select_one('link[href*="css/pages/upstream"]') is not None
    assert doc.select_one('script[type="module"][src*="js/pages/upstream"]') is not None


async def test_the_first_paint_is_light_and_the_heavy_cards_load_as_fragments(page: Any, pages_app: Any) -> None:
    await pages_app.seed_traffic()
    response = await page.get(PAGE)
    doc = parse_html(response.text)
    deferred = {node.get("id") for node in doc.select("section.page-card--lazy[hx-get]")}
    assert {"buckets", "routing", "cooldowns", "breakers", "hosts", "retries"} <= deferred
    for card_id in deferred:
        node = doc.select_one(f"section#{card_id}")
        assert node.get("hx-trigger") == "load"
        assert node.get("hx-get", "").startswith(f"{PAGE}/fragment/{card_id}")
        assert not node.select("[data-setting-key]")  # settings arrive with the fragment, not the first paint
    for card_id in ("health", "429-timeline", "trace", "failures"):
        assert card_id not in deferred
    assert len(response.text) < 260_000, len(response.text)
    assert find_style_issues(response.text, "upstream page") == []


# ============================================================================================ caller text


async def test_hostile_text_is_inert_in_cards_drawers_and_testers(page: Any, pages_app: Any, inert: Any) -> None:
    await pages_app.seed_traffic()
    created = await page.api(
        "POST",
        "routing-rules",
        json={"pattern": "games.roblox.com/v1/x" + HOSTILE["img"], "mode": "prefer_direct", "note": HOSTILE["script"]},
    )
    assert created.status_code == 201, created.text
    rule_id = created.json()["item"]["id"]
    response = await page.get(PAGE)
    inert(response.text, "upstream page")
    for card in _cards():
        fragment = await page.fragment(PAGE_ID, card.id)
        inert(fragment.text, f"upstream {card.id}")
    routing = await page.fragment(PAGE_ID, "routing")
    assert "&lt;img src=x onerror=alert(1)&gt;" in routing.text  # shown, as text
    for path, params in (
        ("/admin/upstream/routing-rule", {"id": rule_id}),
        ("/admin/upstream/routing-test", {"target": "games.roblox.com/v1/x" + HOSTILE["img"]}),
        ("/admin/upstream/routing-test", {"target": HOSTILE["js_url"]}),
        ("/admin/upstream/bucket", {"key": "endpoint:" + HOSTILE["img"]}),
        (f"{PAGE}/fragment/trace", {"request_id": HOSTILE["attr"]}),
    ):
        answer = await page.get(path, params=params, htmx=True)
        assert answer.status_code == 200, (path, answer.text[:300])
        inert(answer.text, path)
    drawer = parse_html((await page.get("/admin/upstream/routing-rule", params={"id": rule_id})).text)
    pattern = drawer.select_one("#routing-edit-pattern")
    assert pattern is not None
    assert HOSTILE["img"] in (pattern.get("value") or "")  # a form value, never markup


# ============================================================================================ one source of truth


async def test_the_numbers_equal_the_api_for_the_same_range(page: Any, pages_app: Any) -> None:
    await pages_app.seed_traffic()
    cards = (await page.api("GET", "upstream/egress")).json()
    health = await page.doc(f"{PAGE}/fragment/health")
    for item in cards["items"]:
        article = health.select_one(f'article[data-egress="{item["egress"]}"]')
        assert article is not None
        numbers = article.select_one("dl.g3-egress__numbers").text()
        assert numbers.startswith(f"Calls to Roblox {item['calls']:,}"), (item["egress"], numbers)
    failures = (await page.api("GET", "upstream/failures")).json()
    doc = await page.doc(f"{PAGE}/fragment/failures")
    assert f"of {failures['total']:,}" in _count(doc) if failures["total"] else _count(doc) == "No rows"
    assert sum(item["count"] for item in failures["items"]) >= 2  # the 503 and the 429 of the seeding plan
    hosts = (await page.api("GET", "upstream/hosts")).json()
    hosts_doc = await page.doc(f"{PAGE}/fragment/hosts")
    assert f"of {hosts['total']:,}" in _count(hosts_doc)
    buckets = (await page.api("GET", "upstream/buckets")).json()
    buckets_doc = await page.doc(f"{PAGE}/fragment/buckets")
    assert f"of {buckets['total']:,}" in _count(buckets_doc.select_one("#upstream-buckets"))
    timeline = (await page.api("GET", "upstream/429-timeline")).json()
    timeline_doc = await page.doc(f"{PAGE}/fragment/429-timeline")
    assert f"Roblox 429s in this range: {timeline['totals']['total']:,}" in timeline_doc.text()
    internal = (await page.api("GET", "upstream/internal-calls")).json()
    internal_doc = await page.doc(f"{PAGE}/fragment/internal-calls")
    assert len(internal_doc.select("#internal-calls tbody tr")) == len(internal["items"])


async def test_the_failures_log_filters_pages_and_exports_with_the_api_names(page: Any, pages_app: Any) -> None:
    await pages_app.seed_traffic()
    doc = await page.doc(PAGE, params={"egress": "direct"})
    table = doc.select_one('#failures [data-table="upstream_failures"]')
    assert table is not None
    names = {n.get("name") for n in table.select("form[data-dt-state] [name]")}
    assert names >= {"q", "egress", "page", "page_size", "sort", "order"}
    chosen = table.select_one('select[name="egress"] option[selected]')
    assert chosen is not None
    assert chosen.get("value") == "direct"
    api = (await page.api("GET", "upstream/failures", params={"egress": "direct"})).json()
    rows = table.select("tbody tr[data-row-id]")
    assert len(rows) == len(api["items"])
    assert all("Direct" in row.text() for row in rows)
    export = table.select_one('a[data-export][href*="format=csv"]')
    assert export is not None
    href = export.get("href")
    assert href.startswith("/admin/api/v1/upstream/failures?")
    assert "egress=direct" in href
    download = await page.api("GET", href)
    assert download.status_code == 200
    assert download.headers["content-type"].startswith("text/csv")


@pytest.mark.parametrize(
    ("path", "params"),
    [
        (PAGE, {"page": "abc"}),
        (PAGE, {"page_size": "7", "sort": "bogus", "order": "sideways"}),
        (PAGE, {"egress": "<b>", "q": "x" * 500}),
        (PAGE, {"range": "forever"}),
        (PAGE, {"range": "custom", "from": "yesterday"}),
        (PAGE, {"request_id": "not-a-request-id"}),
        (PAGE, {"page": "99999999"}),
        (f"{PAGE}/fragment/buckets", {"page": "0", "sort": "nope"}),
        (f"{PAGE}/fragment/hosts", {"page_size": "9999"}),
        (f"{PAGE}/fragment/trace", {"request_id": "0" * 64}),
        ("/admin/upstream/bucket", {"key": ""}),
        ("/admin/upstream/bucket", {"key": "x" * 900}),
        ("/admin/upstream/routing-rule", {"id": "abc"}),
        ("/admin/upstream/routing-rule", {"id": "0"}),
        ("/admin/upstream/routing-rule", {"id": "99999999999999999999999"}),
        ("/admin/upstream/routing-test", {"target": ""}),
        ("/admin/upstream/routing-test", {"target": "/"}),
    ],
    ids=lambda value: value if isinstance(value, str) else "-".join(value),
)
async def test_no_filter_range_or_bad_value_ever_fails_the_page(
    page: Any, pages_app: Any, path: str, params: dict[str, str]
) -> None:
    await pages_app.seed_traffic()
    response = await page.get(path, params=params, htmx=path != PAGE)
    assert response.status_code == 200, (path, params, response.text[:300])
    if path == PAGE:
        assert "data-card-error" not in response.text, params


# ============================================================================================ actions go to the API


async def test_routing_rules_are_added_tested_edited_and_deleted_through_the_api(page: Any, pages_app: Any) -> None:
    doc = await page.doc(f"{PAGE}/fragment/routing")
    form = doc.select_one('form[data-api-url="/admin/api/v1/routing-rules"]')
    assert form is not None
    assert form.get("data-api-method") == "POST"
    assert "No routing rules" in doc.text()
    body = {"pattern": "games.roblox.com/v1/games/*", "mode": "prefer_direct", "reason": "page test"}
    refused = await page.api("POST", "routing-rules", json=body, csrf=False)
    assert refused.status_code == 403
    created = await page.api("POST", "routing-rules", json=body)
    assert created.status_code == 201, created.text
    rule_id = created.json()["item"]["id"]
    listed = await page.doc(f"{PAGE}/fragment/routing")
    row = listed.select_one(f'tr[data-row-id="routing-{rule_id}"]')
    assert row is not None
    assert row.get("data-drawer-src") == f"/admin/upstream/routing-rule?id={rule_id}"
    drawer = await page.doc("/admin/upstream/routing-rule", params={"id": rule_id})
    edit = drawer.select_one("form[data-api-method=PATCH]")
    assert edit.get("data-api-url") == f"/admin/api/v1/routing-rules/{rule_id}"
    delete = drawer.select_one("#dlg-routing-delete form")
    assert delete.get("data-api-url") == f"/admin/api/v1/routing-rules/{rule_id}"
    assert delete.get("data-api-method") == "DELETE"
    tested = await page.doc("/admin/upstream/routing-test", params={"target": "https://games.roblox.com/v1/games/1"})
    assert f"Rule #{rule_id}" in tested.text()
    assert "Prefer direct" in tested.text()
    api = (await page.api("GET", "routing-rules/test", params={"target": "games.roblox.com/v1/games/1"})).json()
    assert api["rule"]["id"] == rule_id
    gone = await page.api("DELETE", f"routing-rules/{rule_id}", json={"reason": "page test"})
    assert gone.status_code == 200, gone.text
    missing = await page.doc("/admin/upstream/routing-rule", params={"id": rule_id})
    assert "No routing rule has that id" in missing.text()


async def test_the_reset_dialog_posts_a_required_reason_with_csrf(page: Any, pages_app: Any) -> None:
    rid = await _too_many(pages_app)
    assert rid
    doc = await page.doc(PAGE)
    dialog = doc.select_one("#dlg-upstream-reset form[data-api-form]")
    assert dialog is not None
    assert dialog.get("data-api-url") == "/admin/api/v1/upstream/reset"
    assert dialog.select_one('textarea[name="reason"][required]') is not None
    cooldowns = await page.doc(f"{PAGE}/fragment/cooldowns")
    assert cooldowns.select_one('[data-action="upstream-reset"][data-dialog-open="dlg-upstream-reset"]') is not None
    assert "thumbnails.roblox.com/v1/too-many" in cooldowns.text()
    assert (await page.api("POST", "upstream/reset", json={"reason": "x"}, csrf=False)).status_code == 403
    assert (await page.api("POST", "upstream/reset", json={})).status_code == 422
    done = await page.api("POST", "upstream/reset", json={"reason": "page test"})
    assert done.status_code == 200, done.text
    assert done.json()["cleared"]["cooldowns_cleared"] >= 1
    after = await page.doc(f"{PAGE}/fragment/cooldowns")
    assert "No cooldowns are open" in after.text()


async def test_a_bucket_key_with_slashes_and_braces_reaches_the_override_api_as_one_segment(page: Any) -> None:
    created = await page.api(
        "POST", "upstream-limits", json={"bucket_key": TEMPLATE_KEY, "per_min": 30, "burst": 3, "reason": "page test"}
    )
    assert created.status_code == 201, created.text
    drawer = await page.doc("/admin/upstream/bucket", params={"key": TEMPLATE_KEY})
    form = drawer.select_one("form[data-api-method=PATCH]")
    assert form is not None
    url = form.get("data-api-url")
    assert url == "/admin/api/v1/upstream-limits/" + quote(TEMPLATE_KEY, safe="")
    assert "/" not in url.removeprefix("/admin/api/v1/upstream-limits/")
    changed = await page.api("PATCH", url, json={"per_min": 24, "burst": 2, "reason": "page test"})
    assert changed.status_code == 200, changed.text
    assert changed.json()["item"]["per_min"] == 24
    listed = await page.doc(f"{PAGE}/fragment/buckets")
    assert TEMPLATE_KEY in listed.select_one("#upstream-limits").text()
    removed = await page.api("DELETE", url, json={"reason": "page test"})
    assert removed.status_code == 200, removed.text


# ============================================================================================ the explainer


async def test_the_trace_explains_a_real_request(page: Any, pages_app: Any) -> None:
    request_id = await _too_many(pages_app)
    api = (await page.api("GET", f"upstream/trace/{request_id}")).json()
    assert api["found"]
    doc = await page.doc(f"{PAGE}/fragment/trace", params={"request_id": request_id.lower()})
    reasons = [node.text() for node in doc.select(".g3-reasons li")]
    assert len(reasons) == len(api["reasons"])
    assert reasons[0].startswith(api["reasons"][0][:40])
    assert "thumbnails.roblox.com/v1/too-many" in doc.text()
    link = doc.select_one(".g3-trace__link a")
    assert link is not None
    assert link.get("href") == f"/admin/upstream?request_id={request_id}#trace"
    deep = await page.doc(PAGE, params={"request_id": request_id})
    assert deep.select_one("#trace .g3-reasons") is not None
    bad = await page.doc(f"{PAGE}/fragment/trace", params={"request_id": "nope"})
    assert "26 character Roxy-Request-Id" in bad.text()
    assert bad.select_one("#trace-request-id[aria-invalid=true]") is not None


# ============================================================================================ empty database


async def test_an_empty_database_explains_every_card(page: Any) -> None:
    texts = {}
    for card in ("failures", "429-timeline", "cooldowns", "breakers", "routing", "retries", "buckets", "challenges"):
        texts[card] = (await page.doc(f"{PAGE}/fragment/{card}")).text()
    assert "No failed requests in this range" in texts["failures"]
    assert "No 429s from Roblox in this range. Good." in texts["429-timeline"]
    assert "No cooldowns are open" in texts["cooldowns"]
    assert "Every breaker is closed" in texts["breakers"]
    assert "No routing rules" in texts["routing"]
    assert "No refused or failed requests in this range" in texts["retries"]
    assert "No rate changes in this range" in texts["buckets"]
    assert "No calls to Roblox in this range" in texts["challenges"]
    trace = (await page.doc(f"{PAGE}/fragment/trace")).text()
    assert re.search(r"Paste the Roxy-Request-Id", trace)
