"""The Audit page (`/admin/audit`, plan 14.1 and 9.7): the reference page's integration tests.

What this is
    Tests against the real app with data written by the real services (`pages_app.seed_all()`: traffic through the
    proxy, settings changes through `SettingsService` with hostile reasons, audit rows with hostile targets and
    documents): the page and its fragments answer 200 for an admin and redirect otherwise, every registry card is
    there, the table pages, sorts, searches and filters on the server with the API's parameter names and never fails
    on a bad value, the numbers equal `GET /admin/api/v1/audit`, the drawer shows a diff and the revert form, the
    revert works through the settings API (CSRF and audit included), hostile text stays inert everywhere, and an empty
    database says why it is empty.

Why it exists
    The Audit page is the pattern the other seventeen pages copy; these tests are the pattern their tests copy
    (`tests/integration/pages/test_page_<page>.py`).

What to read next
    `roxy/admin/pages/audit.py`, `tests/e2e/test_page_audit.py` (the same page in a browser).
"""

from __future__ import annotations

import csv
import io
from typing import Any

import pytest

from roxy.admin.pages import registry
from roxy.admin.pages.testing import HOSTILE, parse_html
from roxy.core.style_guard import find_style_issues

PAGE = "/admin/audit"
TTL_CHANGES = {"action": "setting.update", "target": "setting:cache_ttl_seconds"}


async def test_the_page_and_its_fragments_need_a_signed_in_admin(anon: Any) -> None:
    for path in (PAGE, f"{PAGE}/fragment/log", f"{PAGE}/fragment/entry?entry=1"):
        response = await anon.get(path)
        assert response.status_code == 302, path
        assert response.headers["location"] == "/admin"


async def test_an_empty_log_explains_itself(page: Any) -> None:
    doc = await page.doc(PAGE, params={"q": "nothing-matches-this"})
    log = doc.select_one("section#log")
    assert log is not None
    assert "No audit entries match" in log.text()
    assert "Every change in Roxy is written here" in log.text()


async def test_every_registry_card_and_the_v1_promises_are_on_the_page(page: Any, pages_app: Any) -> None:
    await pages_app.seed_all()
    doc = await page.doc(PAGE)
    for card in registry.cards_for("audit"):
        if card.fragment_only:
            assert doc.select_one(f"#{card.id}") is None
            fragment = await page.fragment("audit", card.id, entry=1)
            assert fragment.status_code == 200
        else:
            assert doc.select_one(f"section#{card.id}[data-card]") is not None, card.id
    table = doc.select_one('#log [data-table="audit_log"]')
    assert table is not None
    assert table.get("data-dt-src", "").startswith("/admin/audit/fragment/log")
    assert {n.get("name") for n in table.select("form[data-dt-state] [name]")} >= {
        "q",
        "action",
        "actor",
        "target",
        "page",
        "page_size",
        "sort",
        "order",
        "range",
    }
    export = table.select_one('a[data-export][href*="format=csv"]')
    assert export is not None
    assert export.get("href").startswith("/admin/api/v1/audit?")
    assert doc.select_one('link[href*="css/pages/audit"]') is not None
    assert doc.select_one('script[type="module"][src*="js/pages/audit"]') is not None
    assert find_style_issues(str(doc.text()), "audit") == []


async def test_hostile_text_is_inert_on_the_page_the_fragment_and_the_drawer(
    page: Any, pages_app: Any, inert: Any
) -> None:
    await pages_app.seed_all()
    response = await page.get(PAGE)
    inert(response.text, "audit page")
    assert "&lt;img src=x onerror=alert(1)&gt;" in response.text  # shown, as text
    assert find_style_issues(response.text, "audit page") == []
    fragment = await page.fragment("audit", "log", q="rules_endpoint_block")
    inert(fragment.text, "audit fragment")
    entry_id = pages_app.seeded["audit"]["record_ids"][0]
    drawer = await page.fragment("audit", "entry", entry=entry_id)
    assert drawer.status_code == 200
    inert(drawer.text, "audit entry")
    doc = parse_html(drawer.text)
    cells = [node.text() for node in doc.select(".audit-diff td")]
    assert any(HOSTILE["img"] in cell for cell in cells)
    assert "<script>" not in drawer.text
    assert 'dir="auto"' in drawer.text  # bidirectional text is isolated (caller_text)


async def test_table_numbers_equal_the_api_for_the_same_filters(page: Any, pages_app: Any) -> None:
    await pages_app.seed_all()
    for params in ({}, {"action": "setting.update"}, {"actor": "admin:*"}, {"target": "setting:*"}, {"q": "cache"}):
        api = (await page.api("GET", "audit", params=params)).json()
        doc = await page.doc(f"{PAGE}/fragment/log", params={"range": "all", **params})
        count = doc.select_one(".dt__count").text()
        if api["total"]:
            assert f"of {api['total']:,}" in count, (params, count, api["total"])
        else:
            assert count == "No rows"
        rows = [row.get("data-row-id") for row in doc.select("tbody tr[data-row-id]")]
        assert rows == [f"audit-{item['id']}" for item in api["items"]], params


async def test_server_paging_sorting_and_search_use_the_api_names(page: Any, pages_app: Any) -> None:
    await pages_app.seed_all()
    total = (await page.api("GET", "audit")).json()["total"]
    assert total > 10
    first = await page.doc(f"{PAGE}/fragment/log", params={"page_size": 10, "page": 1, "sort": "id", "order": "asc"})
    ids = [int(r.get("data-row-id").split("-")[1]) for r in first.select("tbody tr[data-row-id]")]
    assert ids == sorted(ids)
    assert len(ids) == 10
    second = await page.doc(f"{PAGE}/fragment/log", params={"page_size": 10, "page": 2, "sort": "id", "order": "asc"})
    later = [int(r.get("data-row-id").split("-")[1]) for r in second.select("tbody tr[data-row-id]")]
    assert later
    assert min(later) > max(ids)
    assert first.select_one('th[data-col="id"]').get("aria-sort") == "ascending"
    searched = await page.doc(f"{PAGE}/fragment/log", params={"q": "export.download"})
    assert all("export.download" in row.text() for row in searched.select("tbody tr[data-row-id]"))


@pytest.mark.parametrize(
    "params",
    [
        {"page": "abc"},
        {"page": "0"},
        {"page_size": "7"},
        {"sort": "bogus"},
        {"order": "sideways"},
        {"q": "x" * 500},
        {"action": "a" * 300},
        {"range": "forever"},
        {"range": "custom", "from": "yesterday"},
        {"entry": "-1"},
        {"page": "99999999"},
    ],
    ids=lambda p: "-".join(p),
)
async def test_no_filter_or_range_ever_fails_the_page(page: Any, pages_app: Any, params: dict[str, str]) -> None:
    await pages_app.seed_traffic()
    for path in (PAGE, f"{PAGE}/fragment/log"):
        response = await page.get(path, params=params)
        assert response.status_code == 200, (path, params, response.text[:300])
        assert "data-card-error" not in response.text, (path, params)


async def test_the_range_filters_the_log_and_all_shows_everything(page: Any, pages_app: Any, page_admin: Any) -> None:
    await pages_app.seed_all()
    everything = (await page.api("GET", "audit")).json()["total"]
    pages_app.clock.advance(7200)  # past the idle timeout too: sign in again
    assert (await pages_app.harness.login(page_admin)).status_code == 200
    now = int(pages_app.clock.now())
    last_hour = (await page.api("GET", "audit", params={"from": now - 3600, "to": now + 60})).json()
    assert last_hour["total"] < everything  # only the new sign-in
    recent = await page.doc(f"{PAGE}/fragment/log", params={"range": "1h"})
    assert recent.select_one(".dt__count").text() == f"Showing 1 to {last_hour['total']} of {last_hour['total']}"
    total = everything + last_hour["total"]
    whole = await page.doc(f"{PAGE}/fragment/log", params={"range": "all"})
    assert f"of {total:,}" in whole.select_one(".dt__count").text()
    default = await page.doc(PAGE)  # the Audit page opens on the whole log
    assert f"of {total:,}" in default.select_one("#log .dt__count").text()


async def test_the_drawer_shows_the_diff_and_the_revert_form_of_a_settings_change(page: Any, pages_app: Any) -> None:
    await pages_app.seed_all()
    api = (await page.api("GET", "audit", params=TTL_CHANGES)).json()
    newest = api["items"][0]
    doc = parse_html((await page.fragment("audit", "entry", entry=newest["id"])).text)
    changes = doc.select(".audit-diff tbody tr")
    assert changes
    form = doc.select_one("form.audit-revert")
    assert form is not None
    assert form.get("data-api-url").startswith("/admin/api/v1/settings/history/")
    assert form.get("data-on-success") == "refresh"
    assert doc.select_one('[data-confirm-field][hidden] input[name="confirm_high_risk"]') is not None
    manage = doc.select_one(".audit-entry__manage a")
    assert manage.get("href") == "/admin/settings?key=cache_ttl_seconds"
    other = (await page.api("GET", "audit", params={"action": "export.download"})).json()["items"][0]
    plain = parse_html((await page.fragment("audit", "entry", entry=other["id"])).text)
    assert plain.select_one("form.audit-revert") is None
    assert "nothing to revert" in plain.text()


async def test_the_revert_form_posts_to_the_settings_api_with_csrf_and_is_audited(page: Any, pages_app: Any) -> None:
    await pages_app.seed_all()
    api = (await page.api("GET", "audit", params=TTL_CHANGES)).json()
    newest = api["items"][0]
    doc = parse_html((await page.fragment("audit", "entry", entry=newest["id"])).text)
    url = doc.select_one("form.audit-revert").get("data-api-url")
    refused = await page.api("POST", url, json={"reason": "undo"}, csrf=False)
    assert refused.status_code == 403
    done = await page.api("POST", url, json={"reason": "Put it back " + HOSTILE["img"]})
    assert done.status_code == 200, done.text
    assert pages_app.ctx.settings.int("cache_ttl_seconds") == 150
    reverts = (await page.api("GET", "audit", params={"action": "setting.revert"})).json()
    assert reverts["total"] == 1
    page_doc = await page.doc(f"{PAGE}/fragment/log", params={"action": "setting.revert"})
    assert "Put it back" in page_doc.text()


async def test_unknown_and_invalid_entries_say_so_in_the_drawer(page: Any) -> None:
    for entry, text in (("999999", "No audit entry has that id"), ("abc", "not valid"), ("", "not valid")):
        response = await page.fragment("audit", "entry", entry=entry)
        assert response.status_code == 200
        assert text in response.text
        assert "data-card-error" in response.text


async def test_the_export_link_downloads_through_the_api_with_the_filters(page: Any, pages_app: Any) -> None:
    await pages_app.seed_all()
    doc = await page.doc(PAGE, params={"action": "setting.update"})
    href = doc.select_one('#log a[data-export][href*="format=csv"]').get("href")
    assert "action=setting.update" in href
    response = await page.api("GET", href)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    rows = list(csv.reader(io.StringIO(response.text)))
    assert rows[0][0] == "Entry"
    assert len(rows) - 1 == (await page.api("GET", "audit", params={"action": "setting.update"})).json()["total"]


async def test_links_into_the_audit_page_keep_working(page: Any, pages_app: Any) -> None:
    await pages_app.seed_all()
    history = await page.doc(PAGE, params={"target": "setting:cache_ttl_seconds"})
    chosen = history.select_one('select[name="target"] option[value="setting:cache_ttl_seconds"]')
    assert chosen is not None
    assert chosen.get("selected") is not None
    rows = history.select("#log tbody tr[data-row-id]")
    assert len(rows) == 2
    deep = await page.get(PAGE, params={"entry": "1"})
    assert deep.status_code == 200
