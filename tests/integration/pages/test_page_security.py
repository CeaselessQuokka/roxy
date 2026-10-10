"""The Security page (`/admin/security`, plan 14.1): sign-ins, probes, crawls, fingerprints, CSP reports, sessions,
trusted devices, passkeys and recovery codes.

What this is
    Integration tests against the real app with data that went through the real proxy and the real auth flow
    (`pages_app.seed_traffic()`: probes with a `javascript:` URL, hostile User-Agents and places; a robots.txt
    crawl, a CSP report and a request filter refusal with hostile text added here). They prove: the page and every
    fragment answer 200 for an admin and redirect otherwise; every registry card and every inline setting of its
    anchors is there; a table's own requests answer that table alone; numbers equal the API's; hostile text is inert
    on the page, in every fragment and in the drawer; the actions post to the API with CSRF and the second factor
    the API asks for; no filter, range or bad value ever fails the page; and an empty database explains itself.

Why it exists
    P11 page rules (security, truth, help, settings) and the v1 sections of rows 4, 25, 27 to 30 and 32.

What to read next
    `roxy/admin/pages/security.py`, `tests/e2e/test_page_security.py` (the same page in a browser).
"""

from __future__ import annotations

import csv
import io
import json
import re
from typing import Any
from urllib.parse import quote

import pytest

from roxy.admin.pages import registry
from roxy.admin.pages.testing import HOSTILE, parse_html
from roxy.core.style_guard import find_style_issues

PAGE = "/admin/security"
CARDS = [c.id for c in registry.cards_for("security")]
TABLE_PARTS = {
    "logins": "table",
    "probes": "table",
    "probe-summary": "table",
    "crawls": "table",
    "csp-reports": "table",
}
FP_TABS = ("headers", "agents", "blocked", "ignored")


async def seed_security(pages_app: Any) -> None:
    """Traffic through the proxy plus what the plan does not send: a crawl, a CSP report, a refused request."""
    await pages_app.seed_traffic()
    client = pages_app.harness.new_client()
    await client.get("/robots.txt", headers={"User-Agent": HOSTILE["img"], "X-Forwarded-For": "198.51.100.77"})
    report = {
        "csp-report": {
            "document-uri": "https://testserver/admin/" + HOSTILE["img"],
            "blocked-uri": HOSTILE["js_url"],
            "violated-directive": "script-src-elem",
            "effective-directive": "script-src-elem",
            "source-file": "https://testserver/" + HOSTILE["script"],
            "disposition": "enforce",
        }
    }
    await client.post(
        "/csp-report",
        content=json.dumps(report).encode(),
        headers={"Content-Type": "application/csp-report", "X-Forwarded-For": "198.51.100.78"},
    )
    # A value header with hostile text: its values are fingerprinted (the drawer lists them).
    await client.get(
        "/games.roblox.com/v1/games?universeIds=42",
        headers={"X-Roxy-Test": HOSTILE["img"], "X-Forwarded-For": "203.0.113.90", "User-Agent": "Roblox/WinInet"},
    )
    # A request filter refusing a header name: the Blocked tab counts its header names and User-Agent.
    rule = await _admin_api(
        pages_app,
        "POST",
        "protection/header-rules",
        {"needle": "x-roxy-blocked", "scope": "key", "mode": "exact", "reason": "test"},
    )
    assert rule.status_code == 200, rule.text
    await pages_app.ctx.rules.reload()
    refused = await client.get(
        "/games.roblox.com/v1/games?universeIds=43",
        headers={"X-Roxy-Blocked": "1", "X-Forwarded-For": "203.0.113.91", "User-Agent": HOSTILE["script"]},
    )
    assert refused.status_code >= 400
    # Aggregated events (CSP reports, blocked fingerprints) are written once their minute has closed.
    pages_app.clock.advance(61)
    await pages_app.flush()


async def _admin_api(pages_app: Any, method: str, path: str, body: Any) -> Any:
    harness = pages_app.harness
    token = await harness.csrf()
    return await harness.http.request(method, f"/admin/api/v1/{path}", json=body, headers=harness.headers(csrf=token))


# ============================================================================================ access


async def test_the_page_and_its_fragments_need_a_signed_in_admin(anon: Any) -> None:
    for path in (
        PAGE,
        *(f"{PAGE}/fragment/{card}" for card in CARDS),
        f"{PAGE}/fragment/fingerprints?part=header&name=a",
    ):
        response = await anon.get(path)
        assert response.status_code == 302, path
        assert response.headers["location"] == "/admin"


async def test_every_card_renders_and_every_fragment_answers(page: Any, pages_app: Any) -> None:
    await seed_security(pages_app)
    doc = await page.doc(PAGE)
    assert len(doc.select("h1")) == 1
    for card in registry.cards_for("security"):
        assert doc.select_one(f"section#{card.id}[data-card]") is not None, card.id
        response = await page.fragment("security", card.id)
        assert response.status_code == 200, card.id
        assert "data-card-error" not in response.text, (card.id, response.text[:400])
        fragment = parse_html(response.text)
        assert fragment.select_one(f"section#{card.id}[data-card]") is not None, card.id
    assert doc.select_one('link[href*="css/pages/security"]') is not None
    assert doc.select_one('script[type="module"][src*="js/pages/security"]') is not None
    assert find_style_issues(doc.text(), "security") == []


async def test_the_v1_tables_and_controls_are_in_their_cards(page: Any, pages_app: Any) -> None:
    await seed_security(pages_app)
    expected = {
        "logins": ['[data-table="admin_logins"]'],
        "probes": ['[data-table="probes"]'],
        "probe-summary": ['[data-table="probe_summary"]'],
        "crawls": ['[data-table="crawls"]'],
        "fingerprints": [
            '[data-table="fingerprint_headers"]',
            '[data-table="fingerprint_user_agents"]',
            '[data-table="blocked_fingerprints"]',
            '[data-table="ignored_headers"]',
        ],
        "csp-reports": ['[data-table="csp_reports"]'],
        "sessions": ['[data-action="sessions-sign-out-everywhere"]', "form[data-api-form]"],
        "trusted-devices": [],
        "passkeys": ['[data-action="passkey-add"]'],
        "recovery-codes": ['[data-action="recovery-regenerate"]'],
    }
    for card, selectors in expected.items():
        doc = parse_html((await page.fragment("security", card)).text)
        for selector in selectors:
            assert doc.select(f"section#{card} {selector}"), (card, selector)


async def test_every_inline_setting_of_the_admin_access_card_is_there(page: Any) -> None:
    doc = parse_html((await page.fragment("security", "admin-access")).text)
    keys = {node.get("data-setting-key") for node in doc.select("section#admin-access [data-setting-key]")}
    expected = {spec.key for spec in registry.settings_for("security#admin-access")}
    assert expected
    assert keys == expected
    # Every one of them needs a fresh second factor to change (the settings API's admin_security rule).
    assert len(doc.select("section#admin-access form.setting[data-fresh-mfa]")) == len(expected)
    text = doc.select_one("section#admin-access").text()
    assert "You are signing in from" in text
    assert "Admin allowlist" in text


# ============================================================================================ tables


def _top_level(html: str) -> list[Any]:
    return list(parse_html(html).children)


async def test_a_tables_own_requests_answer_that_table_alone(page: Any, pages_app: Any) -> None:
    await seed_security(pages_app)
    requests = [(card, {"part": part}) for card, part in TABLE_PARTS.items()]
    requests += [("fingerprints", {"part": tab}) for tab in FP_TABS]
    for card, params in requests:
        response = await page.fragment("security", card, **params, q="", page_size=10)
        assert response.status_code == 200, (card, params)
        roots = _top_level(response.text)
        assert len(roots) == 1, (card, params, [r.tag for r in roots])
        assert roots[0].tag == "div"
        assert roots[0].get("data-dt") is not None, (card, params)
        assert parse_html(response.text).select_one("section[data-card]") is None
    doc = await page.doc(PAGE)
    probes = doc.select_one('#probes [data-table="probes"]')
    assert probes.get("data-dt-src").startswith("/admin/security/fragment/probes?")
    assert "part=table" in probes.get("data-dt-src")
    assert probes.get("data-dt-address") is not None  # the page's main table keeps its state in the address
    for name in ("admin_logins", "probe_summary", "crawls", "csp_reports"):
        table = doc.select_one(f'[data-table="{name}"]')
        if table is not None:
            assert table.get("data-dt-address") is None, name


@pytest.mark.parametrize(
    ("card", "api_path", "params"),
    [
        ("logins", "security/logins", {}),
        ("logins", "security/logins", {"result": "failure"}),
        ("logins", "security/logins", {"result": "success"}),
        ("probes", "security/probes", {}),
        ("probes", "security/probes", {"signature": "Non-Roblox URL"}),
        ("probe-summary", "security/probes/summary", {}),
        ("probe-summary", "security/probes/summary", {"q": "via"}),
        ("crawls", "security/crawls", {}),
        ("csp-reports", "security/csp-reports", {}),
        ("csp-reports", "security/csp-reports", {"directive": "script-src-elem"}),
    ],
    ids=lambda value: str(value).replace("/", "-") if not isinstance(value, dict) else "-".join(value) or "all",
)
async def test_table_numbers_equal_the_api_for_the_same_filters(
    page: Any, pages_app: Any, card: str, api_path: str, params: dict[str, str]
) -> None:
    await seed_security(pages_app)
    api = (await page.api("GET", api_path, params=params)).json()
    doc = parse_html((await page.fragment("security", card, part="table", **params)).text)
    count = doc.select_one(".dt__count").text()
    if api["total"]:
        assert f"of {api['total']:,}" in count, (card, params, count, api["total"])
    else:
        assert count == "No rows", (card, params, count)
    assert len(doc.select("tbody tr[data-row-id]")) == len(api["items"])


@pytest.mark.parametrize(
    ("tab", "api_path"),
    [
        ("headers", "security/fingerprints/headers"),
        ("agents", "security/fingerprints/user-agents"),
        ("blocked", "security/fingerprints/blocked"),
        ("ignored", "security/fingerprints/ignored"),
    ],
)
async def test_fingerprint_tabs_equal_the_api(page: Any, pages_app: Any, tab: str, api_path: str) -> None:
    await seed_security(pages_app)
    api = (await page.api("GET", api_path)).json()
    doc = parse_html((await page.fragment("security", "fingerprints", part=tab)).text)
    count = doc.select_one(".dt__count").text()
    if api["total"]:
        assert f"of {api['total']:,}" in count, (tab, count, api["total"])
    else:
        assert count == "No rows"
    card = parse_html((await page.fragment("security", "fingerprints")).text)
    badge = card.select_one(f"#fp-tab-{tab} .count-badge").text()
    assert badge == f"{api['total']:,}"


async def test_seeded_security_events_are_listed(page: Any, pages_app: Any) -> None:
    await seed_security(pages_app)
    logins = (await page.api("GET", "security/logins")).json()
    assert logins["total"] >= 1  # this test's own sign-in
    probes = (await page.api("GET", "security/probes")).json()
    assert probes["total"] >= 3
    crawls = (await page.api("GET", "security/crawls")).json()
    assert crawls["total"] == 1
    csp = (await page.api("GET", "security/csp-reports")).json()
    assert csp["total"] == 1
    doc = await page.doc(PAGE)
    assert len(doc.select("#probes tbody tr[data-row-id]")) == min(25, probes["total"])
    subtitle = doc.select_one("#logins .card__sub").text()
    assert re.search(r"\d+ attempts?, \d+ failed", subtitle), subtitle


# ============================================================================================ hostile text


async def test_hostile_text_is_inert_on_the_page_in_every_fragment_and_the_drawer(
    page: Any, pages_app: Any, inert: Any
) -> None:
    await seed_security(pages_app)
    response = await page.get(PAGE)
    inert(response.text, "security page")
    assert find_style_issues(response.text, "security page") == []
    for card in CARDS:
        inert((await page.fragment("security", card)).text, card)
    for tab in FP_TABS:
        inert((await page.fragment("security", "fingerprints", part=tab, page_size=250)).text, tab)
    probes = await page.fragment("security", "probes", part="table", page_size=100)
    assert "javascript:alert(document.cookie)" in parse_html(probes.text).text()  # shown, as text
    csp = await page.fragment("security", "csp-reports")
    assert "&lt;img src=x onerror=alert(1)&gt;" in csp.text
    agents = await page.fragment("security", "fingerprints", part="agents", page_size=250)
    assert "&lt;script&gt;alert(&#39;roxy&#39;)&lt;/script&gt;" in agents.text
    drawer = await page.fragment("security", "fingerprints", part="header", name="x-roxy-test")
    assert drawer.status_code == 200
    inert(drawer.text, "header drawer")
    assert "&lt;img src=x onerror=alert(1)&gt;" in drawer.text
    assert 'dir="auto"' in drawer.text


async def test_a_header_row_opens_its_drawer_by_an_encoded_url(page: Any, pages_app: Any) -> None:
    await seed_security(pages_app)
    doc = parse_html((await page.fragment("security", "fingerprints", part="headers", q="x-roxy")).text)
    row = doc.select_one("tbody tr[data-drawer-src]")
    assert row is not None
    src = row.get("data-drawer-src")
    assert src.startswith("/admin/security/fragment/fingerprints?")
    assert "part=header" in src
    assert "name=x-roxy-test" in src
    assert row.get("data-drawer-title") == "Header x-roxy-test"
    drawer = parse_html((await page.get(src.replace("&amp;", "&"))).text)
    urls = {form.get("data-api-url") for form in drawer.select("form[data-api-form]")}
    assert "/admin/api/v1/security/fingerprints/headers/x-roxy-test/values" in urls
    assert "/admin/api/v1/security/fingerprints/headers/x-roxy-test" in urls
    assert "/admin/api/v1/security/fingerprints/ignored" in urls
    assert drawer.select_one('form[data-api-form] input[name="name"]').get("value") == "x-roxy-test"


@pytest.mark.parametrize("name", ["", "a\x01b", "x" * 300])
async def test_a_bad_header_name_says_so_in_the_drawer(page: Any, name: str) -> None:
    response = await page.fragment("security", "fingerprints", part="header", name=name)
    assert response.status_code == 200
    if len(name) > 120:  # cut to 120 characters: a header never recorded
        assert "data-card-error" not in response.text
        assert "No values are stored for this header" in response.text
    else:
        assert "data-card-error" in response.text
        assert "not valid" in response.text


def test_api_path_keeps_a_caller_name_inside_one_segment() -> None:
    from roxy.admin.pages.security import api_path

    assert api_path("security", "fingerprints", "headers", "../../settings") == (
        "/admin/api/v1/security/fingerprints/headers/..%2F..%2Fsettings"
    )
    assert api_path("a", "x y?z#w") == "/admin/api/v1/a/x%20y%3Fz%23w"
    assert quote("//evil", safe="") in api_path("x", "//evil")


# ============================================================================================ actions


async def test_fingerprint_actions_need_csrf_and_are_audited(page: Any, pages_app: Any) -> None:
    await seed_security(pages_app)
    values = "/admin/api/v1/security/fingerprints/headers/x-roxy-test/values"
    refused = await page.api("DELETE", values, csrf=False)
    assert refused.status_code == 403
    done = await page.api("DELETE", values)
    assert done.status_code == 200, done.text
    assert done.json()["values_removed"] >= 1
    audit = (await page.api("GET", "audit", params={"action": "fingerprints.clear_values"})).json()
    assert audit["total"] == 1
    ignored = await page.api("POST", "security/fingerprints/ignored", json={"name": "x-roxy-test", "reason": "noise"})
    assert ignored.status_code == 200, ignored.text
    drawer = parse_html((await page.fragment("security", "fingerprints", part="header", name="x-roxy-test")).text)
    record = [f for f in drawer.select("form[data-api-form]") if f.get("data-api-method") == "DELETE"]
    assert any(f.get("data-api-url") == "/admin/api/v1/security/fingerprints/ignored/x-roxy-test" for f in record)
    assert "Not recorded" in drawer.text()
    tab = parse_html((await page.fragment("security", "fingerprints", part="ignored")).text)
    assert "x-roxy-test" in tab.text()
    for form in drawer.select("form[data-api-form]"):
        assert form.get("data-on-success") == "refresh"
        assert form.get("data-refresh") == "fingerprints"


async def test_sessions_are_listed_and_another_one_can_be_ended(
    page: Any, pages_app: Any, page_admin: Any, inert: Any
) -> None:
    other = pages_app.harness.new_client()
    signed = await pages_app.harness.login(page_admin, client=other, ua="OtherBrowser/1.0 " + HOSTILE["img"])
    assert signed.status_code == 200
    response = await page.fragment("security", "sessions")
    inert(response.text, "sessions")
    for cookie in pages_app.harness.http.cookies.jar:
        if "session" in cookie.name:
            assert cookie.value not in response.text  # never the session cookie
    doc = parse_html(response.text)
    rows = doc.select("section#sessions tr[data-session-row]")
    assert len(rows) == 2
    current = [row for row in rows if "is-current" in row.classes()]
    assert len(current) == 1
    assert "This browser" in current[0].text()
    other_row = next(row for row in rows if "is-current" not in row.classes())
    assert "OtherBrowser/1.0" in other_row.text()
    url = other_row.select_one("form[data-api-form]").get("data-api-url")
    assert re.fullmatch(r"/admin/api/v1/security/sessions/[0-9a-f]{16}/revoke", url)
    assert (await page.api("POST", url, json={}, csrf=False)).status_code == 403
    ended = await page.api("POST", url, json={})
    assert ended.status_code == 200, ended.text
    assert ended.json() == {"revoked": 1, "signed_out": False}
    gone = await other.get("/admin/api/v1/auth/session", headers=pages_app.harness.headers())
    assert gone.status_code == 401
    after = parse_html((await page.fragment("security", "sessions")).text)
    assert len(after.select("tr[data-session-row]")) == 1
    dialogs = {d.get("id"): d for d in after.select("dialog")}
    assert dialogs["dlg-sessions-all"].select_one("form").get("data-api-url") == (
        "/admin/api/v1/security/sessions/revoke-all"
    )
    assert dialogs["dlg-sessions-all"].select_one("form").get("data-on-success") == "reload"


async def test_trusted_devices_are_listed_and_revoked(page: Any, pages_app: Any, page_admin: Any) -> None:
    await pages_app.settings(admin_trusted_devices_enabled=1)
    other = pages_app.harness.new_client()
    signed = await pages_app.harness.login(page_admin, client=other, trust=True)
    assert signed.status_code == 200
    doc = parse_html((await page.fragment("security", "trusted-devices")).text)
    rows = doc.select("section#trusted-devices tr[data-device-row]")
    assert len(rows) == 1
    assert "This browser is not trusted" in doc.text()
    url = rows[0].select_one("form[data-api-form]").get("data-api-url")
    assert re.fullmatch(r"/admin/api/v1/security/trusted-devices/\d+/revoke", url)
    revoked = await page.api("POST", url, json={})
    assert revoked.status_code == 200, revoked.text
    after = parse_html((await page.fragment("security", "trusted-devices")).text)
    assert not after.select("tr[data-device-row]")
    assert "No device is trusted" in after.text()


async def test_recovery_codes_show_counts_only_and_regenerate_needs_a_fresh_factor(page: Any) -> None:
    doc = parse_html((await page.fragment("security", "recovery-codes")).text)
    assert doc.select_one("[data-recovery-remaining]").text() == "10"
    assert doc.select_one("[data-recovery-total]").text() == "10"
    url = doc.select_one("#dlg-recovery-new form").get("data-api-url")
    assert url == "/admin/api/v1/security/recovery-codes/regenerate"
    page.make_mfa_stale()
    stale = await page.api("POST", url, json={})
    assert stale.status_code == 403
    assert stale.json()["error"]["code"] == "reauth_required"
    await page.fresh_mfa()
    fresh = await page.api("POST", url, json={})
    assert fresh.status_code == 200, fresh.text
    codes = fresh.json()["codes"]
    assert len(codes) == 10
    html = (await page.fragment("security", "recovery-codes")).text
    assert not any(code in html for code in codes)  # shown once, by the page script, never rendered


async def test_passkeys_are_added_renamed_and_deleted_through_the_cards_urls(
    page: Any, pages_app: Any, inert: Any
) -> None:
    from roxy.admin.auth.testing import SoftwarePasskey

    doc = parse_html((await page.fragment("security", "passkeys")).text)
    add = doc.select_one("form[data-passkey-add]")
    assert "You have no passkey yet" in doc.text()
    await page.fresh_mfa()
    options = await page.api("POST", add.get("data-options-url"), json={})
    assert options.status_code == 200, options.text
    key = SoftwarePasskey()
    credential = key.register(options.json()["Options"], origin=pages_app.harness.site_origin)
    made = await page.api("POST", add.get("data-verify-url"), json={"credential": credential, "name": HOSTILE["img"]})
    assert made.status_code == 200, made.text
    response = await page.fragment("security", "passkeys")
    inert(response.text, "passkeys")
    listed = parse_html(response.text)
    item = listed.select_one("li[data-passkey]")
    assert item is not None
    assert HOSTILE["img"] in item.text()
    rename = item.select_one("form[data-api-form]")
    assert rename.get("data-api-method") == "PATCH"
    page.make_mfa_stale()
    stale = await page.api("PATCH", rename.get("data-api-url"), json={"name": "Laptop"})
    assert stale.status_code == 403
    await page.fresh_mfa()
    renamed = await page.api("PATCH", rename.get("data-api-url"), json={"name": "Laptop"})
    assert renamed.status_code == 200, renamed.text
    delete = listed.select_one("dialog form[data-api-form]")
    assert delete.get("data-api-method") == "DELETE"
    deleted = await page.api("DELETE", delete.get("data-api-url"), json={})
    assert deleted.status_code == 200, deleted.text
    assert "You have no passkey yet" in (await page.fragment("security", "passkeys")).text


async def test_clear_buttons_link_to_the_data_pages_reset_form(page: Any) -> None:
    doc = await page.doc(PAGE)
    links = {node.get("href") for node in doc.select('a[data-action="reset-family"]')}
    assert "/admin/data?families=logins#resets" in links
    assert "/admin/data?families=probes#resets" in links
    for card in ("crawls", "fingerprints"):
        fragment = parse_html((await page.fragment("security", card)).text)
        link = fragment.select_one('a[data-action="reset-family"]')
        assert link.get("href") == f"/admin/data?families={card}#resets"


async def test_the_export_links_download_through_the_api(page: Any, pages_app: Any) -> None:
    await seed_security(pages_app)
    doc = parse_html((await page.fragment("security", "probes", part="table")).text)
    href = doc.select_one('a[data-export][href*="format=csv"]').get("href").replace("&amp;", "&")
    assert href.startswith("/admin/api/v1/security/probes?")
    response = await page.api("GET", href)
    assert response.status_code == 200, response.text
    rows = list(csv.reader(io.StringIO(response.text)))
    assert rows[0][0] == "When"
    assert len(rows) - 1 == (await page.api("GET", "security/probes")).json()["total"]


# ============================================================================================ robustness


BAD_PARAMS = [
    {"page": "abc"},
    {"page": "0"},
    {"page_size": "7"},
    {"sort": "bogus"},
    {"order": "asc"},
    {"order": "sideways"},
    {"q": "x" * 500},
    {"result": "bogus"},
    {"signature": "s" * 400},
    {"ip": "<img src=x>"},
    {"kind": "bogus"},
    {"directive": "<img src=x onerror=alert(1)>"},
    {"range": "forever"},
    {"range": "custom", "from": "yesterday"},
    {"part": "bogus"},
    {"page": "99999999"},
]


@pytest.mark.parametrize("params", BAD_PARAMS, ids=lambda p: "-".join(f"{k}" for k in p))
async def test_no_filter_or_range_ever_fails_the_page(
    page: Any, pages_app: Any, inert: Any, params: dict[str, str]
) -> None:
    await pages_app.seed_traffic()
    requests: list[tuple[str, dict[str, str]]] = [(PAGE, {}), *((f"{PAGE}/fragment/{card}", {}) for card in CARDS)]
    requests += [(f"{PAGE}/fragment/{card}", {"part": part}) for card, part in TABLE_PARTS.items()]
    requests += [(f"{PAGE}/fragment/fingerprints", {"part": tab}) for tab in FP_TABS]
    for path, base in requests:
        sent = {**base, **params} if "part" not in params else {**params}
        response = await page.get(path, params=sent)
        assert response.status_code == 200, (path, sent, response.text[:300])
        assert "data-card-error" not in response.text, (path, sent)
        inert(response.text, f"{path} {sent}")


async def test_newest_first_logs_say_so_instead_of_failing(page: Any, pages_app: Any) -> None:
    await pages_app.seed_traffic()
    doc = parse_html((await page.fragment("security", "probes", part="table", order="asc")).text)
    assert "newest first only" in doc.text()
    assert not doc.select("button[data-dt-sort]")  # a fixed order has no sort buttons


async def test_an_empty_database_explains_itself(page: Any) -> None:
    doc = await page.doc(PAGE)
    assert "No probes in this range" in doc.select_one("#probes").text()
    texts = {
        "crawls": "No crawler fetched robots.txt in this range",
        "csp-reports": "No CSP reports in this range",
        "probe-summary": "No probe signatures in this range",
    }
    for card, text in texts.items():
        assert text in parse_html((await page.fragment("security", card)).text).text(), card
    fingerprints = parse_html((await page.fragment("security", "fingerprints")).text).text()
    assert "No header names recorded yet" in fingerprints
    assert "No request filter refused anything in this range" in fingerprints
    assert "You have no passkey yet" in (await page.fragment("security", "passkeys")).text
