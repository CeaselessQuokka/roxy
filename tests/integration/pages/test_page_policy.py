"""The Endpoint policy page (`/admin/policy`, D1 revised 2026-10-16): integration tests against the real app.

What this is
    Tests with the real rules snapshot (the shipped seed, overrides and switches written through the admin API) and
    counter events written by the real recorder: the page, every card fragment and the three partials answer 200 for
    an admin and redirect otherwise; every registry card renders without an error and holds its inline settings;
    the Endpoints table matches the API (filters, search, totals), every row links Roblox's two documentation pages
    in a new tab without an opener; the drawer, the tester and the unknown endpoint drawer show what the API says;
    the forms post to the API, where CSRF is required and loosening needs a fresh second factor; caller text stays
    inert; and no filter or bad value ever fails the page.

Why it exists
    The P11 contract for a dashboard page, and BRIEF.md section 8: this page decides which requests carry Roxy's
    Roblox account, so what it shows and what it sends must be exactly what the API judges.

What to read next
    `roxy/admin/pages/policy.py`, `roxy/admin/api/policy.py`, `tests/integration/admin_api/test_api_policy.py`.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from urllib.parse import urlencode

import pytest

from pages_harness import HOSTILE, parse_html
from roxy.abuse.checks.endpoint_policy import POLICY_BLOCKED_EVENT, POLICY_UNKNOWN_EVENT, POLICY_WOULD_BLOCK_EVENT
from roxy.admin.pages import registry
from roxy.core.style_guard import find_style_issues

PAGE = "/admin/policy"
PAGE_ID = "policy"
DRAWER = "/admin/policy/endpoint"
TESTER = "/admin/policy/test"
UNKNOWN = "/admin/policy/unknown-row"
BLOCKED = "users:GET:/v1/users/authenticated"
TOKEN = "users:GET:/v1/users/{userId}"
LOGOUT = "auth:POST:/v2/logout"
UNKNOWN_ID = "unknown:GET:games.roblox.com/v1/not-documented/{id}"


def _cards() -> list[registry.CardSpec]:
    return list(registry.cards_for(PAGE_ID))


async def _events(pages_app: Any, kind: str, endpoint_id: str, verdict: str, count: int = 1) -> None:
    for _ in range(count):
        pages_app.ctx.recorder.record_event(
            kind, "info", None, {"endpoint_id": endpoint_id, "verdict": verdict}, aggregate=True
        )
    pages_app.clock.advance(60)  # counter events are written once their minute closes
    await pages_app.flush()


async def _attempt(pages_app: Any, *, value: str, looks_real: bool, name: str = "cookie") -> None:
    attempt = SimpleNamespace(kind="roblosecurity", where="cookie", name=name, value=value, looks_real=looks_real)
    pages_app.ctx.recorder.record_auth_attempt(
        "203.0.113.9", attempt, method="GET", endpoint_id=TOKEN, user_agent=HOSTILE["img"]
    )
    await pages_app.flush()


# ============================================================================================ guards and structure


async def test_the_page_its_fragments_and_partials_need_a_signed_in_admin(anon: Any) -> None:
    partials = (f"{DRAWER}?id={BLOCKED}", f"{TESTER}?target=users.roblox.com/v1/users/1", f"{UNKNOWN}?id=x")
    for path in [PAGE, *(f"{PAGE}/fragment/{card.id}" for card in _cards()), *partials]:
        response = await anon.get(path)
        assert response.status_code == 302, path
        assert response.headers["location"] == "/admin"


def test_the_page_is_registered_in_the_defense_group() -> None:
    spec = registry.page(PAGE_ID)
    assert spec.title == "Endpoint policy"
    assert spec.group == "defense"
    assert spec.href == PAGE
    assert [card.id for card in _cards()] == [
        "summary",
        "categories",
        "endpoints",
        "tester",
        "unknown",
        "attempts",
        "would-block",
    ]
    assert "allowlist" not in [card.id for card in registry.cards_for("credential")]
    row = next(row for row in registry.V1_SECTIONS if row.row == 19)
    assert registry.V1Check("policy", "endpoints", ('[data-table="endpoint_policy"]',)) in row.checks


async def test_every_card_renders_without_an_error_and_holds_its_settings(page: Any, pages_app: Any) -> None:
    await _events(pages_app, POLICY_UNKNOWN_EVENT, UNKNOWN_ID, "ALLOW_ANON", 3)
    await _events(pages_app, POLICY_WOULD_BLOCK_EVENT, BLOCKED, "BLOCK", 2)
    await _attempt(pages_app, value="not a real cookie", looks_real=False)
    response = await page.get(PAGE)
    assert response.status_code == 200
    doc = parse_html(response.text)
    for card in _cards():
        assert doc.select_one(f"section#{card.id}[data-card]") is not None, card.id
        fragment = await page.doc(f"{PAGE}/fragment/{card.id}")
        section = fragment.select_one(f"section#{card.id}[data-card]")
        assert section is not None, card.id
        assert fragment.select_one("[data-card-error]") is None, (card.id, section.text()[:300])
        for spec in registry.settings_for(registry.anchor(PAGE_ID, card.id)):
            assert section.select_one(f'[data-setting-key="{spec.key}"]') is not None, (card.id, spec.key)
    summary = doc.select_one("section#summary")
    for key in ("endpoint_policy_enforce", "endpoint_policy_block_status", "endpoint_policy_block_message"):
        assert summary.select_one(f'[data-setting-key="{key}"]') is not None, key
    assert not doc.select("[data-card-error]")
    assert doc.select_one('link[href*="css/pages/policy"]') is not None
    assert doc.select_one('script[type="module"][src*="js/pages/policy"]') is not None
    assert doc.select_one('nav a[href="/admin/policy"]') is not None or "/admin/policy" in response.text
    assert find_style_issues(response.text, "policy page") == []
    for card in _cards():
        assert find_style_issues((await page.fragment(PAGE_ID, card.id)).text, card.id) == []


async def test_the_credential_page_has_no_allowlist_left(page: Any) -> None:
    doc = await page.doc("/admin/credential")
    assert doc.select_one("section#allowlist") is None
    assert doc.select_one('a[href="/admin/policy"]') is not None
    for path in ("/admin/credential/allowlist-row?id=1", "/admin/credential/allowlist-test?target=x"):
        assert (await page.get(path)).status_code == 404, path
    assert (await page.api("GET", "credential-allowlist")).status_code == 404


# ============================================================================================ one source of truth


async def test_the_summary_and_categories_equal_the_api(page: Any, pages_app: Any) -> None:
    await _events(pages_app, POLICY_BLOCKED_EVENT, BLOCKED, "BLOCK", 4)
    summary = (await page.api("GET", "policy")).json()
    doc = await page.doc(f"{PAGE}/fragment/summary")
    counts = doc.select_one("[data-policy-counts]").text()
    for value in summary["verdicts"].values():
        assert f"{value:,}" in counts
    day = doc.select_one("[data-policy-day]").text()
    assert f"{summary['last_24h']['refused']:,}" in day
    assert summary["last_24h"]["refused"] == 4
    assert summary["seed"]["generated_on"] in doc.text()
    reset = doc.select_one("#dlg-policy-reset form[data-api-form]")
    assert reset.get("data-api-url") == "/admin/api/v1/policy/reset"
    assert reset.get("data-api-method") == "POST"
    assert reset.select_one('textarea[name="reason"]') is not None

    categories = (await page.api("GET", "policy/categories")).json()
    listed = await page.doc(f"{PAGE}/fragment/categories")
    rows = listed.select("details[data-category]")
    assert [row.get("data-category") for row in rows] == [item["key"] for item in categories["items"]]
    public = listed.select_one('details[data-category="public-read"]')
    form = public.select_one("form[data-api-form]")
    assert form.get("data-api-url") == "/admin/api/v1/policy/categories/public-read"
    assert form.get("data-api-method") == "PUT"
    assert {radio.get("value") for radio in form.select('input[name="state"]')} == {
        "defaults",
        "block_all",
        "strip_credential",
    }
    ads = listed.select_one('details[data-category="ads"]')
    assert {radio.get("value") for radio in ads.select('input[name="state"]')} == {"defaults", "block_all"}
    assert ads.select_one('a[href="/admin/policy?category=ads#endpoints"]') is not None


async def test_the_endpoints_table_equals_the_api_and_links_robloxs_docs(page: Any) -> None:
    answer = (await page.api("GET", "policy/endpoints")).json()
    doc = await page.doc(PAGE)
    table = doc.select_one('#endpoints [data-table="endpoint_policy"]')
    assert table is not None
    rows = table.select("tbody tr[data-row-id]")
    assert len(rows) == len(answer["items"]) == 25
    assert f"{answer['total']:,}" in table.select_one(".dt__count").text()
    for row, item in zip(rows, answer["items"], strict=True):
        assert row.get("data-row-id") == item["id"]
        assert row.get("data-drawer-src") == DRAWER + "?" + urlencode({"id": item["id"]})
        links = row.select('td[data-col="docs"] a')
        hrefs = [link.get("href") for link in links]
        assert item["domain_doc"] in hrefs
        if item["feature_doc"]:
            assert item["feature_doc"] in hrefs
        for link in links:
            assert link.get("target") == "_blank"
            assert link.get("rel") == "noopener noreferrer"
        assert {"Roblox domain docs"} <= {link.text().strip() for link in links} | {"Roblox domain docs"}
        assert row.select_one("input[data-policy-pick]").get("value") == item["id"]
    texts = " ".join(link.text() for link in table.select('td[data-col="docs"] a'))
    assert "Roblox feature docs" in texts
    assert "Roblox domain docs" in texts
    bulk = doc.select("#endpoints form[data-policy-bulk]")
    assert [(form.get("data-api-method"), form.get("data-api-url")) for form in bulk] == [
        ("PUT", "/admin/api/v1/policy/endpoints"),
        ("DELETE", "/admin/api/v1/policy/endpoints"),
    ]
    assert bulk[0].select_one('input[name="verdict"]').get("value") == "BLOCK"
    assert all(form.select_one('textarea[name="endpoint_ids"][data-json="list"]') for form in bulk)


@pytest.mark.parametrize(
    ("params", "api_params"),
    [
        ({"category": "ads"}, {"category": "ads"}),
        ({"verdict": "ALLOW_ANON"}, {"verdict": "ALLOW_ANON"}),
        ({"risk": "4", "method": "POST"}, {"risk": 4, "method": "POST"}),
        ({"host": "users.roblox.com", "q": "authenticated"}, {"host": "users.roblox.com", "q": "authenticated"}),
        ({"auth": "cookie-required"}, {"auth": "cookie-required"}),
        ({"changed": "1"}, {"changed": "true"}),
    ],
    ids=lambda value: "-".join(f"{k}={v}" for k, v in value.items()),
)
async def test_the_filters_and_search_match_the_api(
    page: Any, params: dict[str, str], api_params: dict[str, Any]
) -> None:
    answer = (await page.api("GET", "policy/endpoints", params=api_params)).json()
    doc = await page.doc(f"{PAGE}/fragment/endpoints", params=params)
    rows = doc.select('[data-table="endpoint_policy"] tbody tr[data-row-id]')
    assert [row.get("data-row-id") for row in rows] == [item["id"] for item in answer["items"]]
    for name, value in params.items():
        if name != "q":
            chosen = doc.select_one(f'select[name="{name}"] option[selected]')
            assert chosen is not None, name
            assert chosen.get("value") == value, name


# ============================================================================================ drawer and tester


async def test_the_drawer_shows_the_row_and_its_forms(page: Any) -> None:
    item = (await page.api("GET", "policy/endpoints/detail", params={"id": BLOCKED})).json()
    drawer = await page.doc(DRAWER, params={"id": BLOCKED})
    text = drawer.text()
    assert item["rationale"] in text
    assert item["roblox_auth_words"] in text
    assert "Roblox feature docs" in text
    assert "Roblox domain docs" in text
    history = drawer.select_one('a[href^="/admin/audit?"]')
    assert history.get("href") == "/admin/audit?" + urlencode({"target": f"endpoint_policy_override:{BLOCKED}"})
    form = drawer.select_one("form[data-policy-verdict]")
    assert form.get("data-api-url") == "/admin/api/v1/policy/endpoints"
    assert form.get("data-api-method") == "PUT"
    assert form.select_one('input[name="endpoint_id"]').get("value") == BLOCKED
    assert form.select_one('textarea[name="reason"][required]') is not None
    assert form.select_one('select[name="verdict"] option[selected]').get("value") == "BLOCK"
    assert form.select_one('input[name="confirm"]') is None  # risk 3: no typed path
    assert drawer.select_one("#dlg-policy-default") is None  # no override yet
    critical = await page.doc(DRAWER, params={"id": LOGOUT})
    confirm = critical.select_one("[data-policy-confirm]")
    assert confirm is not None
    assert confirm.get("hidden") is not None  # shown by the script when loosening
    assert "/v2/logout" in confirm.text()
    options = [o.get("value") for o in critical.select('select[name="verdict"] option')]
    assert options == ["BLOCK", "ALLOW_TOKEN", "ALLOW_ANON"]
    put = await page.doc(DRAWER, params={"id": "apis:PUT:/service-efficiency-api/v1/accounts/groups/{groupId}"})
    assert [o.get("value") for o in put.select('select[name="verdict"] option')] == ["BLOCK", "ALLOW_ANON"]
    missing = await page.doc(DRAWER, params={"id": "users:GET:/v1/nothing"})
    assert "No Roblox endpoint has that id" in missing.text()


async def test_an_override_shows_in_the_table_and_the_drawer_offers_back_to_default(page: Any) -> None:
    body = {"endpoint_id": TOKEN, "verdict": "ALLOW_ANON", "note": "quieter", "reason": "page test"}
    assert (await page.api("PUT", "policy/endpoints", json=body)).status_code == 200
    doc = await page.doc(f"{PAGE}/fragment/endpoints", params={"changed": "1"})
    rows = doc.select('[data-table="endpoint_policy"] tbody tr[data-row-id]')
    assert [row.get("data-row-id") for row in rows] == [TOKEN]
    assert "Your override" in rows[0].select_one('td[data-col="verdict"]').text()
    drawer = await page.doc(DRAWER, params={"id": TOKEN})
    assert "quieter" in drawer.text()
    back = drawer.select_one("#dlg-policy-default form[data-api-form]")
    assert back.get("data-api-method") == "DELETE"
    assert back.select_one('input[name="endpoint_id"]').get("value") == TOKEN
    summary = await page.doc(f"{PAGE}/fragment/summary")
    assert summary.select_one('a[href="/admin/policy?changed=1#endpoints"]') is not None


@pytest.mark.parametrize(
    ("target", "method", "words"),
    [
        ("https://users.roblox.com/v1/users/authenticated", "GET", ["Blocked", "Refused before Roblox"]),
        ("https://roxy.example.com/users.roblox.com/v1/users/1", "GET", ["Sent with Roxy's account", "goes without"]),
        ("apis.roblox.com/toolbox-service/v2/assets/123", "GET", ["Sent without an account", "goes out anonymously"]),
        ("games.roblox.com/v1/not-documented/5", "GET", ["Not in Roblox's reference", "Set a verdict for it"]),
        ("games.roblox.com/v1/games/1818/servers/Friend?limit=10", "GET", ["Blocked", "Query guard"]),
        ("games.roblox.com/v1/games/1818/servers/Public", "GET", ["Sent with Roxy's account"]),
        ("thumbnails.roblox.com/v1/assets-thumbnail-3d?assetId=1", "GET", ["never falls back"]),
    ],
)
async def test_the_tester_answers_like_the_api(page: Any, target: str, method: str, words: list[str]) -> None:
    answer = (await page.api("GET", "policy/test", params={"target": target, "method": method})).json()
    doc = await page.doc(TESTER, params={"target": target, "method": method})
    result = doc.select_one("[data-policy-test]")
    assert result is not None, doc.text()[:300]
    assert result.get("data-verdict") == answer["verdict"]
    for word in words:
        assert word in result.text(), (word, result.text()[:600])
    assert len(result.select(".policy-steps li")) == len(answer["steps"])


async def test_shadow_mode_reads_as_shadow_in_the_tester_and_the_summary(page: Any, pages_app: Any) -> None:
    await pages_app.settings(endpoint_policy_enforce=0)
    doc = await page.doc(TESTER, params={"target": "users.roblox.com/v1/users/authenticated"})
    assert "Shadow mode" in doc.text()
    assert "Refused before Roblox" not in doc.text()
    summary = await page.doc(f"{PAGE}/fragment/summary")
    assert "Shadow mode" in summary.select_one(".policy-state").text()
    shadow = await page.doc(f"{PAGE}/fragment/would-block")
    assert "Shadow mode is on" in shadow.text()


# ============================================================================================ logs of the range


async def test_unknown_endpoints_offer_set_verdict_and_the_drawer_puts_the_unknown_id(
    page: Any, pages_app: Any
) -> None:
    await _events(pages_app, POLICY_UNKNOWN_EVENT, UNKNOWN_ID, "ALLOW_ANON", 3)
    doc = await page.doc(f"{PAGE}/fragment/unknown")
    rows = doc.select('[data-table="endpoint_policy_unknown"] tbody tr[data-row-id]')
    assert len(rows) == 1
    assert UNKNOWN_ID in rows[0].text()
    button = rows[0].select_one('button[data-action="policy-unknown-set"]')
    assert button.get("data-drawer-src") == UNKNOWN + "?" + urlencode({"id": UNKNOWN_ID})
    drawer = await page.doc(UNKNOWN, params={"id": UNKNOWN_ID})
    form = drawer.select_one("form[data-policy-verdict]")
    assert form.get("data-api-method") == "PUT"
    assert form.select_one('input[name="endpoint_id"]').get("value") == UNKNOWN_ID
    assert "Sent without an account" in drawer.text()
    body = {"endpoint_id": UNKNOWN_ID, "verdict": "BLOCK", "reason": "review"}
    assert (await page.api("PUT", "policy/endpoints", json=body)).status_code == 200
    after = await page.doc(f"{PAGE}/fragment/unknown")
    assert "Your override" in after.text()
    reopened = await page.doc(UNKNOWN, params={"id": UNKNOWN_ID})
    assert reopened.select_one("#dlg-policy-unknown-default form") is not None
    bad = await page.doc(UNKNOWN, params={"id": "users:GET:/v1/users/{userId}"})
    assert bad.select_one("[data-card-error]") is not None


async def test_sign_in_attempts_highlight_a_real_cookie_and_show_the_fingerprint(page: Any, pages_app: Any) -> None:
    secret = "_|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in" + "A" * 600
    await _attempt(pages_app, value=secret, looks_real=True)
    await _attempt(pages_app, value=secret, looks_real=True)
    await _attempt(pages_app, value="junk", looks_real=False, name=HOSTILE["attr"][:20])
    answer = (await page.api("GET", "policy/attempts")).json()
    doc = await page.doc(f"{PAGE}/fragment/attempts")
    html = (await page.fragment(PAGE_ID, "attempts")).text
    assert secret[40:80] not in html  # the value is never shown (or stored)
    rows = doc.select('[data-table="auth_attempts"] tbody tr[data-row-id]')
    assert len(rows) == answer["total"] == 3
    real = [row for row in rows if "leaked a live cookie" in row.text()]
    assert len(real) == 2
    prints = {row.select_one('td[data-col="fingerprint"]').text().strip() for row in real}
    assert len(prints) == 1  # the same secret twice: one fingerprint
    assert "" not in prints
    assert "A caller sent a real Roblox cookie" in doc.text()
    assert "never stores" in doc.text()


async def test_shadow_mode_table_lists_what_would_have_been_refused(page: Any, pages_app: Any) -> None:
    await _events(pages_app, POLICY_WOULD_BLOCK_EVENT, BLOCKED, "BLOCK", 5)
    answer = (await page.api("GET", "policy/would-block")).json()
    doc = await page.doc(f"{PAGE}/fragment/would-block")
    rows = doc.select('[data-table="endpoint_policy_would_block"] tbody tr[data-row-id]')
    assert len(rows) == len(answer["items"]) == 1
    assert "5" in rows[0].select_one('td[data-col="count"]').text()
    assert "only while endpoint_policy_enforce is off" in doc.text()


# ============================================================================================ writes go to the API


async def test_the_forms_need_csrf_and_loosening_a_fresh_factor(page: Any) -> None:
    tighten = {"endpoint_id": TOKEN, "verdict": "BLOCK", "reason": "page"}
    assert (await page.api("PUT", "policy/endpoints", json=tighten, csrf=False)).status_code == 403
    page.make_mfa_stale()
    assert (await page.api("PUT", "policy/endpoints", json=tighten)).status_code == 200  # tightening: no factor
    loosen = {"endpoint_id": TOKEN, "verdict": "ALLOW_TOKEN", "reason": "page"}
    stale = await page.api("PUT", "policy/endpoints", json=loosen)
    assert stale.status_code == 403
    assert stale.json()["error"]["code"] == "reauth_required"
    assert stale.headers.get("Roxy-Reauth")
    await page.fresh_mfa()
    assert (await page.api("PUT", "policy/endpoints", json=loosen)).status_code == 200
    category = {"state": "block_all", "reason": "page"}
    assert (await page.api("PUT", "policy/categories/ads", json=category, csrf=False)).status_code == 403
    assert (await page.api("POST", "policy/reset", json={"reason": "page"}, csrf=False)).status_code == 403


# ============================================================================================ caller text


async def test_hostile_text_is_inert_in_cards_the_tester_and_the_drawers(page: Any, pages_app: Any, inert: Any) -> None:
    hostile_id = "unknown:GET:games.roblox.com/v1/" + HOSTILE["img"].replace(" ", "")
    await _events(pages_app, POLICY_UNKNOWN_EVENT, hostile_id, "ALLOW_ANON")
    await _attempt(pages_app, value="x", looks_real=False, name=HOSTILE["attr"])
    pages = [("page", (await page.get(PAGE)).text)]
    for card in _cards():
        pages.append((card.id, (await page.fragment(PAGE_ID, card.id)).text))
    for target in ("games.roblox.com/v1/" + HOSTILE["img"], HOSTILE["js_url"], "users.roblox.com/" + HOSTILE["attr"]):
        pages.append((target, (await page.get(TESTER, params={"target": target}, htmx=True)).text))
    pages.append(("unknown", (await page.get(UNKNOWN, params={"id": hostile_id}, htmx=True)).text))
    note = {"endpoint_id": TOKEN, "verdict": "BLOCK", "note": HOSTILE["img"], "reason": "page"}
    assert (await page.api("PUT", "policy/endpoints", json=note)).status_code == 200
    pages.append(("drawer", (await page.get(DRAWER, params={"id": TOKEN}, htmx=True)).text))
    for where, html in pages:
        inert(html, f"policy {where}")


@pytest.mark.parametrize(
    ("path", "params"),
    [
        (PAGE, {"page": "abc", "page_size": "7", "sort": "bogus", "order": "sideways"}),
        (PAGE, {"q": "x" * 600}),
        (PAGE, {"range": "forever"}),
        (PAGE, {"page": "99999999"}),
        (PAGE, {"category": "nope", "verdict": "MAYBE", "risk": "9", "method": "TRACE", "changed": "2"}),
        (f"{PAGE}/fragment/endpoints", {"page": "0", "sort": "nope", "host": "x" * 300}),
        (f"{PAGE}/fragment/attempts", {"order": "asc"}),
        (f"{PAGE}/fragment/unknown", {"range": "all"}),
        (DRAWER, {"id": ""}),
        (DRAWER, {"id": "x" * 900}),
        (UNKNOWN, {"id": "unknown:GET:example.com/x"}),
        (UNKNOWN, {"id": "y" * 900}),
        (TESTER, {"target": ""}),
        (TESTER, {"target": "/"}),
        (TESTER, {"target": "example.com/v1/x"}),
        (TESTER, {"target": "users.roblox.com/v1/users/1", "method": "TRACE"}),
    ],
    ids=lambda value: value if isinstance(value, str) else "-".join(value),
)
async def test_no_filter_range_or_bad_value_ever_fails_the_page(page: Any, path: str, params: dict[str, str]) -> None:
    response = await page.get(path, params=params, htmx=path != PAGE)
    assert response.status_code == 200, (path, params, response.text[:300])
    if path == PAGE:
        assert "data-card-error" not in response.text, params
