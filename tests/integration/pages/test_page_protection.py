"""The Protection page (`/admin/protection`, plan 14.1, 10.9): integration tests against the real app.

What this is
    Tests with data written through the real API and the real proxy (`seed_protection`: User-Agent rules, request
    filters, an endpoint block and rule, bans, deny, bypass and ignored entries, every one carrying hostile text,
    then traffic that each of them refuses, on top of the harness's `traffic_plan()`): the page and every card
    fragment answer 200 for an admin and redirect otherwise; every registry card and every inline setting of the
    Protection anchors is there; each table, filter and drawer works on the server with the API's names and never
    fails on a bad value; the numbers equal the API's for the same query; hostile text stays inert everywhere
    (page, fragments, table requests, drawers); the forms post to API routes that need CSRF (and a fresh second
    factor where the API asks for one); an empty database explains itself.

Why it exists
    The Protection page is the largest page (twenty registry cards plus seven detector cards, seventeen tables);
    these tests pin what the server sends, and `tests/e2e/test_page_protection.py` what a browser does with it.

What to read next
    `roxy/admin/pages/protection.py`, `tests/integration/pages/test_page_audit.py` (the reference page's tests).
"""

from __future__ import annotations

import csv
import io
from typing import Any

import pytest

from roxy.admin.pages import registry
from roxy.admin.pages.testing import HOSTILE, PlannedRequest, parse_html
from roxy.core.style_guard import find_style_issues

PAGE = "/admin/protection"
CARDS = [card.id for card in registry.cards_for("protection")]
TABLES: dict[str, tuple[str, ...]] = {
    "refusals": ("refusals",),
    "throttle": ("watch", "history"),
    "strikes": ("strikes",),
    "throttle-all": ("watch-all",),
    "bans": ("bans",),
    "lists": ("deny", "allow-admin"),
    "bypass": ("bypass",),
    "ua-rules": ("ua",),
    "request-filters": ("filters", "attempts"),
    "endpoint-blocks": ("blocks", "attempts"),
    "endpoint-rules": ("rules", "attempts"),
    "ignored-paths": ("ignored",),
    "spam": ("decisions",),
}
"""Every table of the page by card (the `table=` key of its own fragment requests)."""


async def seed_protection(page: Any, pages_app: Any) -> dict[str, Any]:
    """Rules, lists and bans with hostile text through the API, then traffic each of them refuses."""
    made: dict[str, Any] = {}
    for name, path, body in (
        (
            "ua",
            "protection/ua-rules",
            {
                "needle": "RobloxGameServer",
                "kind": "burst",
                "scope": "global",
                "limit": 3,
                "period": 60,
                "note": HOSTILE["img"],
                "message": "Slow down " + HOSTILE["script"],
            },
        ),
        ("ua_hostile", "protection/ua-rules", {"needle": HOSTILE["img"], "kind": "cooldown", "cooldown": 2.5}),
        ("filter", "protection/header-rules", {"needle": "curl", "header": "User-Agent", "note": HOSTILE["js_url"]}),
        (
            "filter_hostile",
            "protection/header-rules",
            {"needle": "<script>", "scope": "either", "message": HOSTILE["attr"]},
        ),
        (
            "block",
            "protection/endpoint-blocks",
            {"pattern": "catalog.roblox.com/v1/blocked", "message": "Nope " + HOSTILE["img"], "note": HOSTILE["attr"]},
        ),
        (
            "rule",
            "protection/endpoint-rules",
            {"pattern": "users.roblox.com/v1/users", "limit": 2, "period": 60, "message": HOSTILE["unicode"]},
        ),
        (
            "ban",
            "protection/bans",
            {"subject_type": "ip", "subject": "198.51.100.77", "minutes": 60, "message": HOSTILE["img"]},
        ),
        ("ban_place", "protection/bans", {"subject_type": "place", "subject": "606849622", "permanent": True}),
        ("deny", "protection/access/deny", {"cidr": "192.0.2.200/32", "note": HOSTILE["script"]}),
        ("bypass", "protection/access/bypass", {"cidr": "192.0.2.201", "note": HOSTILE["img"], "expires_in_h": 2}),
        ("ignored", "protection/ignored-paths", {"pattern": "favicon-test.txt", "note": HOSTILE["img"]}),
    ):
        response = await page.api("POST", path, json=body)
        assert response.status_code == 200, (name, response.text)
        made[name] = response.json()
    await pages_app.seed_traffic()
    plan = [
        PlannedRequest("/catalog.roblox.com/v1/blocked/1", "203.0.113.90"),
        PlannedRequest("/catalog.roblox.com/v1/blocked/" + HOSTILE["img"], "203.0.113.90"),
        PlannedRequest("/catalog.roblox.com/v1/blocked/" + HOSTILE["js_url"], "203.0.113.91"),
        *(PlannedRequest(f"/users.roblox.com/v1/users/{i}", "203.0.113.92") for i in range(5)),
        PlannedRequest("/games.roblox.com/v1/games?universeIds=77", "198.51.100.77"),
        PlannedRequest("/games.roblox.com/v1/games?universeIds=78", "192.0.2.200"),
        PlannedRequest("/games.roblox.com/v1/games?universeIds=79", "192.0.2.201"),
        PlannedRequest("/games.roblox.com/v1/games?universeIds=80", "203.0.113.93", user_agent="curl/8.4"),
    ]
    await pages_app.seed_traffic(plan)
    return made


# ============================================================================================ access and shape


async def test_the_page_and_its_fragments_need_a_signed_in_admin(anon: Any) -> None:
    for path in (PAGE, *(f"{PAGE}/fragment/{card}" for card in CARDS), f"{PAGE}/fragment/bans?detail=1"):
        response = await anon.get(path)
        assert response.status_code == 302, path
        assert response.headers["location"] == "/admin"


async def test_every_card_renders_on_the_page_and_as_a_fragment(page: Any, pages_app: Any) -> None:
    await seed_protection(page, pages_app)
    doc = await page.doc(PAGE)
    assert len(doc.select("h1")) == 1
    for card in CARDS:
        assert doc.select_one(f"section#{card}[data-card]") is not None, card
        fragment = await page.fragment("protection", card)
        assert fragment.status_code == 200, card
        assert "data-card-error" not in fragment.text, (card, fragment.text[:400])
        node = parse_html(fragment.text).select_one(f"section#{card}[data-card]")
        assert node is not None, card
        assert node.get("data-card-src", "").startswith(f"{PAGE}/fragment/{card}")
    # Only the pipeline renders with the page; the rest are lazy fragments (the 1 GB server's first paint).
    assert doc.select_one("section#pipeline .prot-pipeline") is not None
    lazy = {node.get("id") for node in doc.select("section.page-card--lazy")}
    assert lazy == set(CARDS) - {"pipeline"}
    assert doc.select_one('link[href*="css/pages/protection"]') is not None
    assert doc.select_one('script[type="module"][src*="js/pages/protection"]') is not None


async def test_every_inline_setting_of_the_protection_anchors_is_on_its_card(page: Any) -> None:
    for card in CARDS:
        keys = [spec.key for spec in registry.settings_for(registry.anchor("protection", card))]
        if not keys:
            continue
        doc = parse_html((await page.fragment("protection", card)).text)
        for key in keys:
            assert doc.select_one(f'section#{card} [data-setting-key="{key}"]') is not None, (card, key)


async def test_the_v1_key_elements_are_on_their_cards(page: Any, pages_app: Any) -> None:
    await seed_protection(page, pages_app)
    for row in registry.v1_rows_for("protection"):
        for check in row.checks:
            if check.page != "protection":
                continue
            doc = parse_html((await page.fragment("protection", check.card)).text)
            for selector in check.selectors:
                assert doc.select(f"#{check.card} {selector}"), (row.row, check.card, selector)


# ============================================================================================ hostile text


async def test_hostile_text_is_inert_on_the_page_fragments_tables_and_drawers(
    page: Any, pages_app: Any, inert: Any
) -> None:
    made = await seed_protection(page, pages_app)
    response = await page.get(PAGE)
    inert(response.text, "protection page")
    assert find_style_issues(response.text, "protection page") == []
    seen_escaped = False
    for card in CARDS:
        fragment = await page.fragment("protection", card)
        inert(fragment.text, f"fragment {card}")
        assert find_style_issues(fragment.text, card) == [], card
        seen_escaped = seen_escaped or "&lt;img src=x onerror=alert(1)&gt;" in fragment.text
        for key in TABLES.get(card, ()):
            table = await page.fragment("protection", card, table=key, q="")
            inert(table.text, f"table {card}/{key}")
    assert seen_escaped, "the hostile text should be shown, as text"
    drawers = [
        ("bans", made["ban"]["item"]["id"]),
        ("lists", made["deny"]["item"]["id"]),
        ("bypass", made["bypass"]["item"]["id"]),
        ("ua-rules", made["ua"]["item"]["id"]),
        ("ua-rules", made["ua_hostile"]["item"]["id"]),
        ("request-filters", made["filter_hostile"]["item"]["id"]),
        ("endpoint-blocks", made["block"]["item"]["id"]),
        ("endpoint-rules", made["rule"]["item"]["id"]),
        ("ignored-paths", "favicon-test.txt"),
        ("strikes", "198.51.100.99"),
    ]
    for card, detail in drawers:
        drawer = await page.fragment("protection", card, detail=detail)
        assert drawer.status_code == 200, (card, detail)
        assert "data-card-error" not in drawer.text, (card, detail, drawer.text[:300])
        inert(drawer.text, f"drawer {card} {detail}")
        assert 'dir="auto"' in drawer.text or card == "strikes", card  # caller text is isolated (caller_text)
    attempts = await page.fragment("protection", "endpoint-blocks", table="attempts")
    assert "catalog.roblox.com/v1/blocked/1" in attempts.text
    assert 'href="javascript' not in attempts.text


# ============================================================================================ truth


@pytest.mark.parametrize(
    ("card", "key", "api", "params"),
    [
        ("refusals", "refusals", "protection/refusals", {}),
        ("bans", "bans", "protection/bans", {"state": "all"}),
        ("lists", "deny", "protection/access/deny", {}),
        ("bypass", "bypass", "protection/access/bypass", {}),
        ("ua-rules", "ua", "protection/ua-rules", {}),
        ("request-filters", "filters", "protection/header-rules", {}),
        ("request-filters", "attempts", "protection/header-rules/attempts", {}),
        ("endpoint-blocks", "blocks", "protection/endpoint-blocks", {}),
        ("endpoint-blocks", "attempts", "protection/endpoint-blocks/attempts", {}),
        ("endpoint-rules", "rules", "protection/endpoint-rules", {}),
        ("endpoint-rules", "attempts", "protection/endpoint-rules/attempts", {}),
        ("strikes", "strikes", "protection/strikes", {}),
        ("throttle", "history", "protection/throttle/history", {}),
        ("ignored-paths", "ignored", "protection/ignored-paths", {}),
    ],
)
async def test_table_numbers_equal_the_api(
    page: Any, pages_app: Any, card: str, key: str, api: str, params: dict[str, str]
) -> None:
    await seed_protection(page, pages_app)
    answer = (await page.api("GET", api, params=params)).json()
    doc = parse_html((await page.fragment("protection", card, table=key, **params)).text)
    table = doc.select_one(f"#prot-{key}")
    assert table is not None
    count = table.select_one(".dt__count").text()
    if answer["total"]:
        assert f"of {answer['total']:,}" in count, (card, key, count, answer["total"])
    else:
        assert count == "No rows"
    assert len(table.select("tbody tr[data-row-id]")) == len(answer["items"])
    # A table request answers the table alone: it swaps in place of the old one, never a card inside a card.
    assert doc.select_one("section[data-card]") is None


async def test_the_pipeline_counts_equal_the_api(page: Any, pages_app: Any) -> None:
    await seed_protection(page, pages_app)
    answer = (await page.api("GET", "protection/pipeline")).json()
    doc = parse_html((await page.fragment("protection", "pipeline")).text)
    steps = doc.select(".prot-pipeline .prot-step")
    assert len(steps) == len(answer["checks"])
    for step, check in zip(steps, answer["checks"], strict=True):
        assert check["label"] in step.text()
        if check["kind"] != "marker":
            assert f"{check['refused']:,} refused" in step.text(), (check["name"], step.text())
    assert any(check["refused"] for check in answer["checks"])
    assert f"{answer['evaluated']:,}" in doc.select_one(".prot-stats").text()


async def test_the_refusal_reasons_keep_the_v1_columns_and_the_message_split(page: Any, pages_app: Any) -> None:
    await seed_protection(page, pages_app)
    doc = parse_html((await page.fragment("protection", "refusals")).text)
    labels = [node.text() for node in doc.select("#prot-refusals thead th")]
    for label in ("Reason", "Count", "Status", "Last path", "Unique clients", "Last seen", "Message"):
        assert any(label in text for text in labels), label
    assert "custom message" in doc.text() or "default text" in doc.text()
    assert "Endpoint block" in doc.text()


async def test_attempts_tabs_name_the_rule_that_refused(page: Any, pages_app: Any) -> None:
    await seed_protection(page, pages_app)
    doc = parse_html((await page.fragment("protection", "endpoint-rules", table="attempts")).text)
    cells = [node.text() for node in doc.select('#prot-attempts td[data-col="refused_by"]')]
    assert cells
    assert all("users.roblox.com/v1/users" in cell for cell in cells), cells


async def test_the_ladder_card_has_the_simulation_the_editor_and_restore_defaults(page: Any, pages_app: Any) -> None:
    doc = parse_html((await page.fragment("protection", "ladder")).text)
    steps = [node.text() for node in doc.select(".prot-timeline li")]
    assert steps[0].startswith("1st strike")
    assert "Waits 50 seconds (1 times the normal 50 seconds)" in steps[0]
    assert "Too many requests; please slow down." in steps[0]
    assert steps[-1].startswith("after that")
    assert "drops them back down one rung at a time" in steps[-1]
    assert len(doc.select("[data-ladder-rows] [data-ladder-row]")) == 4
    form = doc.select_one("form[data-ladder-form]")
    assert form.get("data-api-url") == "/admin/api/v1/protection/ladder"
    assert doc.select_one('[data-action="ladder-reset"]') is not None
    assert doc.select_one("dialog#dlg-prot-ladder-reset form[data-api-form]").get("data-api-url") == (
        "/admin/api/v1/protection/ladder/reset"
    )
    await pages_app.settings(throttle_escalation_enabled=0)
    off = parse_html((await page.fragment("protection", "ladder")).text)
    assert "Escalation is off" in off.select_one(".prot-timeline").text()


async def test_the_strike_board_drawer_and_forgive(page: Any, pages_app: Any) -> None:
    await seed_protection(page, pages_app)
    board = (await page.api("GET", "protection/strikes")).json()
    assert board["total"] >= 1
    client = board["items"][0]["ip"]
    drawer = parse_html((await page.fragment("protection", "strikes", detail=client)).text)
    assert client in drawer.text()
    forgive = drawer.select_one('form[data-api-form] [data-action="strike-forgive"]')
    assert forgive is not None
    refused = await page.api("POST", "protection/strikes/forgive", json={"ip": client}, csrf=False)
    assert refused.status_code == 403
    done = await page.api("POST", "protection/strikes/forgive", json={"ip": client, "reason": "test"})
    assert done.status_code == 200
    after = (await page.api("GET", "protection/strikes")).json()
    assert client not in [item["ip"] for item in after["items"]]


# ============================================================================================ forms and the API


async def test_every_form_posts_to_a_protection_api_route_with_its_method(page: Any, pages_app: Any) -> None:
    made = await seed_protection(page, pages_app)
    seen: set[tuple[str, str]] = set()
    paths = [(card, {}) for card in CARDS] + [
        ("bans", {"detail": made["ban"]["item"]["id"]}),
        ("lists", {"detail": made["deny"]["item"]["id"]}),
        ("ua-rules", {"detail": made["ua"]["item"]["id"]}),
        ("request-filters", {"detail": made["filter"]["item"]["id"]}),
        ("endpoint-blocks", {"detail": made["block"]["item"]["id"]}),
        ("endpoint-rules", {"detail": made["rule"]["item"]["id"]}),
        ("ignored-paths", {"detail": "favicon-test.txt"}),
    ]
    for card, params in paths:
        doc = parse_html((await page.fragment("protection", card, **params)).text)
        for form in doc.select("form[data-api-form]"):
            url = form.get("data-api-url", "")
            method = form.get("data-api-method", "POST")
            assert url.startswith(("/admin/api/v1/protection/", "/admin/api/v1/settings/")), (card, url)
            seen.add((method, url.split("?")[0].rsplit("/", 1)[0] if method in ("DELETE", "PATCH") else url))
    methods = {method for method, _ in seen}
    assert {"POST", "PATCH", "DELETE", "PUT"} <= methods, seen


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("POST", "protection/bans", {"subject_type": "ip", "subject": "203.0.113.250", "minutes": 5}),
        ("POST", "protection/access/deny", {"cidr": "203.0.113.251"}),
        ("POST", "protection/ua-rules", {"needle": "csrf-check"}),
        ("POST", "protection/header-rules", {"needle": "csrf-check"}),
        ("POST", "protection/endpoint-blocks", {"pattern": "games.roblox.com/v1/csrf-check"}),
        ("PUT", "protection/ladder", {"tiers": [{"multiplier": 1}]}),
        ("POST", "protection/ua-rules/test", {"user_agent": "x"}),
        ("POST", "protection/limiter/reset", {"scope": "client", "client": "203.0.113.9", "reason": "x"}),
    ],
)
async def test_every_change_the_page_makes_needs_the_csrf_token(page: Any, method: str, path: str, body: Any) -> None:
    refused = await page.api(method, path, json=body, csrf=False)
    assert refused.status_code == 403, refused.text


async def test_arming_and_the_admin_allowlist_need_a_fresh_second_factor(page: Any, pages_app: Any) -> None:
    doc = parse_html((await page.fragment("protection", "spam")).text)
    token = doc.select_one('dialog#dlg-prot-spam-arm input[name="confirm_collateral"]').get("value")
    assert token
    assert len(token) == 32
    page.make_mfa_stale()
    assert (await pages_app.harness.login(page.admin)).status_code == 200
    page.make_mfa_stale()
    armed = await page.api("POST", "protection/spam/arm", json={"confirm_collateral": token, "reason": "test"})
    assert armed.status_code in (401, 403), armed.text
    if armed.status_code == 403:
        assert armed.json()["error"]["code"] == "reauth_required"


async def test_a_ladder_saved_as_the_page_script_sends_it_is_stored_and_simulated(page: Any) -> None:
    body = {
        "tiers": [
            {
                "multiplier": 1,
                "message": "First " + HOSTILE["img"],
                "note": "",
                "action": "throttle",
                "ban_minutes": None,
            },
            {"multiplier": 3, "message": "", "note": HOSTILE["script"], "action": "ban", "ban_minutes": 30},
        ],
        "reason": "test",
    }
    saved = await page.api("PUT", "protection/ladder", json=body)
    assert saved.status_code == 200, saved.text
    doc = parse_html((await page.fragment("protection", "ladder")).text)
    steps = [node.text() for node in doc.select(".prot-timeline li")]
    assert "Is banned for 30 minutes" in steps[1]
    assert "this rung has no message" in steps[1]
    assert len(doc.select("[data-ladder-rows] [data-ladder-row]")) == 2


# ============================================================================================ robustness


@pytest.mark.parametrize(
    "params",
    [
        {"table": "bans", "page": "abc"},
        {"table": "bans", "page": "0"},
        {"table": "bans", "page_size": "7"},
        {"table": "bans", "sort": "bogus"},
        {"table": "bans", "order": "sideways"},
        {"table": "bans", "q": "x" * 500},
        {"table": "bans", "state": "forever", "origin": "x", "detector": "spam_nope", "subject_type": "planet"},
        {"table": "strikes", "order": "asc"},
        {"table": "decisions", "kind": "bogus", "detector": "SPAM-NOPE"},
        {"table": "nope"},
        {"range": "forever"},
        {"range": "custom", "from": "yesterday"},
        {"detail": "abc"},
        {"detail": "999999"},
        {"detail": "-1"},
        {"page": "99999999", "table": "attempts"},
    ],
    ids=lambda p: "-".join(f"{k}" for k in p),
)
async def test_no_filter_range_or_detail_ever_fails_the_page(page: Any, pages_app: Any, params: dict[str, str]) -> None:
    await pages_app.seed_traffic()
    response = await page.get(PAGE, params=params)
    assert response.status_code == 200, (params, response.text[:300])
    assert "data-card-error" not in response.text, params
    for card in ("bans", "strikes", "spam", "endpoint-blocks", "throttle"):
        fragment = await page.fragment("protection", card, **params)
        assert fragment.status_code == 200, (card, params)
        if "detail" not in params:
            assert "data-card-error" not in fragment.text, (card, params, fragment.text[:300])


async def test_unknown_details_say_so_in_the_drawer(page: Any) -> None:
    for card, detail, text in (
        ("bans", "999999", "No ban has that id"),
        ("bans", "abc", "not valid"),
        ("ua-rules", "deadbeef", "No User-Agent rule has that id"),
        ("endpoint-blocks", "424242", "No endpoint block has that id"),
        ("strikes", "not-an-ip", "not a client address"),
        ("ignored-paths", "nothing-here", "No ignored path has that id"),
    ):
        response = await page.fragment("protection", card, detail=detail)
        assert response.status_code == 200
        assert text in response.text, (card, detail, response.text[:400])
        assert "data-card-error" in response.text


async def test_an_empty_database_explains_itself(page: Any) -> None:
    for card, text in (
        ("refusals", "Roxy refused nothing in this range"),
        ("strikes", "Nobody is carrying strikes right now"),
        ("throttle-all", "Nothing has been refused since the emergency limit was switched on"),
        ("bans", "No ban matches"),
        ("ua-rules", "No client rules; every caller uses the ordinary limits"),
        ("request-filters", "No request filters"),
        ("endpoint-blocks", "No endpoint is blocked"),
        ("spam", "No detector decided anything in this range"),
        ("tarpit", "No holds recorded by this worker yet"),
    ):
        response = await page.fragment("protection", card)
        assert response.status_code == 200
        assert text in response.text, (card, text)


async def test_exports_go_through_the_api_with_the_tables_filters(page: Any, pages_app: Any) -> None:
    await seed_protection(page, pages_app)
    doc = parse_html((await page.fragment("protection", "bans", table="bans", state="all")).text)
    href = doc.select_one('#prot-bans a[data-export][href*="format=csv"]').get("href")
    assert href.startswith("/admin/api/v1/protection/bans?")
    assert "state=all" in href
    response = await page.api("GET", href)
    assert response.status_code == 200
    rows = list(csv.reader(io.StringIO(response.text)))
    assert len(rows) - 1 == (await page.api("GET", "protection/bans", params={"state": "all"})).json()["total"]
