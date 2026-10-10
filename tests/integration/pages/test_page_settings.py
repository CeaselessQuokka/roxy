"""The Settings page (`/admin/settings`, plan 14.1, 15.2; v1 Runtime Settings, parity rows 87 and 124): integration
tests against the real app.

What this is
    The page as the server renders it and the API routes its scripts call: the guards, every registry card, the
    editor showing exactly what `GET /admin/api/v1/settings` lists for the same filters (search, group, risk, "only
    what I have changed", "only with an open recommendation"), one page at a time with every setting reachable, the
    `?key=` deep link (v1 names too), bad parameters as notices, the inline settings of the alert and public site
    cards, the history equal to `GET /settings/history` with its drawer and revert (CSRF, audit), import and export
    through the API, the batch save's second factor, and hostile text staying inert everywhere.

Why it exists
    The Settings page is where every runtime knob can be turned; it must show the server's truth, send changes only
    through the settings API (one place for validation, risk, second factor and audit), and never fail (plan P6, 9.16).

What to read next
    `roxy/admin/pages/settings.py`, `tests/e2e/test_page_settings.py`.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from roxy.admin.pages import registry
from roxy.admin.pages.testing import HOSTILE, parse_html
from roxy.config import catalog
from roxy.core.style_guard import find_style_issues

PAGE = "/admin/settings"


def _keys(doc: Any) -> list[str]:
    return [node.get("data-setting-key") for node in doc.select("#editor-results form[data-setting-key]")]


def _api_keys(answer: dict[str, Any]) -> list[str]:
    entries = [entry["key"] for group in answer["groups"] for entry in group["settings"]]
    if answer.get("ranked_keys"):
        order = {key: i for i, key in enumerate(answer["ranked_keys"])}
        entries.sort(key=lambda key: order.get(key, len(order)))
    return entries


async def test_the_page_and_its_fragments_need_a_signed_in_admin(anon: Any) -> None:
    for path in (PAGE, *(f"{PAGE}/fragment/{card.id}" for card in registry.cards_for("settings"))):
        response = await anon.get(path)
        assert response.status_code == 302, path
        assert response.headers["location"] == "/admin"


async def test_every_card_renders_and_the_page_stays_light(page: Any, pages_app: Any) -> None:
    await pages_app.seed_all()
    response = await page.get(PAGE)
    assert response.status_code == 200
    doc = parse_html(response.text)
    assert len(doc.select("h1")) == 1
    for card in registry.cards_for("settings"):
        assert doc.select_one(f"section#{card.id}[data-card]") is not None, card.id
        fragment = await page.fragment("settings", card.id)
        assert fragment.status_code == 200, card.id
        assert "data-card-error" not in fragment.text, (card.id, fragment.text[:400])
        assert find_style_issues(fragment.text, card.id) == []
    assert not doc.select("[data-card-error]")
    assert find_style_issues(response.text, "settings page") == []
    ids = doc.ids()
    assert len(ids) == len(set(ids)), sorted({i for i in ids if ids.count(i) > 1})
    assert doc.select_one('link[href*="css/pages/settings"]') is not None
    assert doc.select_one('script[type="module"][src*="js/pages/settings"]') is not None
    assert len(response.content) < 600_000, len(response.content)  # 25 controls, never the whole catalog at once


async def test_the_v1_runtime_settings_section_has_its_home(page: Any) -> None:
    """Plan 14.1 row 33: the editor holds setting controls; v1's "changed from default" count is there."""
    doc = await page.doc(PAGE)
    editor = doc.select_one("section#editor")
    assert editor is not None
    assert len(editor.select("[data-setting-key]")) == 25
    assert "changed from default" in editor.select_one(".card__sub").text()
    assert editor.select_one('form#editor-filter input[name="q"]') is not None
    assert editor.select_one('input[name="changed"][type="checkbox"]') is not None
    reset_links = editor.select("form[data-setting-key] .setting__links button")
    assert reset_links  # "Reset to default" on every control (parity row 124)


@pytest.mark.parametrize(
    "params",
    [{}, {"q": "cache"}, {"group": "tarpit"}, {"risk": "high"}, {"changed": "1"}, {"has_recommendation": "1"}],
    ids=lambda p: "-".join(f"{k}={v}" for k, v in p.items()) or "all",
)
async def test_the_editor_lists_what_the_api_lists(page: Any, pages_app: Any, params: dict[str, str]) -> None:
    await pages_app.seed_all()
    api_params = {k: ("true" if v == "1" else v) for k, v in params.items()}
    answer = (await page.api("GET", "settings", params={**api_params, "include_text": "false"})).json()
    doc = parse_html((await page.fragment("settings", "editor", **params)).text)
    expected = _api_keys(answer)
    assert _keys(doc) == expected[:25], params
    status = doc.select_one("[data-editor-status]").text()
    assert (f"of {answer['count']:,} settings" in status) if answer["count"] else "No setting matches" in status
    if not answer["count"]:
        assert "No setting matches that." in doc.select_one("#editor-results").text()


async def test_every_setting_is_reachable_page_by_page(page: Any) -> None:
    seen: list[str] = []
    pages = -(-len(catalog.CATALOG) // 100)
    for number in range(1, pages + 1):
        doc = parse_html((await page.fragment("settings", "editor", page=number, page_size=100)).text)
        seen += _keys(doc)
    assert sorted(seen) == sorted(catalog.CATALOG)
    last = parse_html((await page.fragment("settings", "editor", page=99999, page_size=100)).text)
    assert last.select_one(".pager__pos").text() == f"Page {pages} of {pages}"  # past the end: the last page


async def test_a_key_link_shows_that_one_setting_and_v1_names_work(page: Any) -> None:
    doc = await page.doc(PAGE, params={"key": "cache_ttl_seconds"})
    assert _keys(doc) == ["cache_ttl_seconds"]
    item = doc.select_one("#editor-results #cache_ttl_seconds")
    assert item is not None
    assert item.select_one('a[href="/admin/cache#settings"]') is not None  # "Also on" its feature card
    assert doc.select_one('.settings-key-note a[href="/admin/settings"]') is not None
    renamed = next(spec for spec in catalog.CATALOG.values() if spec.renamed_from)
    v1 = await page.doc(PAGE, params={"key": renamed.renamed_from})
    assert _keys(v1) == [renamed.key]
    assert renamed.renamed_from in v1.select_one(f"#{renamed.key}").text()
    unknown = await page.doc(PAGE, params={"key": "no_such_setting"})
    assert len(_keys(unknown)) == 25
    assert "No setting has the key in the address" in unknown.text()


@pytest.mark.parametrize(
    "params",
    [
        {"group": "bogus"},
        {"risk": "extreme"},
        {"page": "abc"},
        {"page_size": "7"},
        {"page": "-5"},
        {"q": "x" * 500},
        {"changed": "maybe"},
        {"key": "<script>"},
        {"range": "forever"},
        {"change": "abc"},
        {"page_size": "100000"},
    ],
    ids=lambda p: "-".join(p),
)
async def test_no_filter_or_value_ever_fails_the_page(page: Any, params: dict[str, str]) -> None:
    for path in (PAGE, f"{PAGE}/fragment/editor"):
        response = await page.get(path, params=params)
        assert response.status_code == 200, (path, params, response.text[:300])
        assert "data-card-error" not in response.text, (path, params)
    history = await page.get(f"{PAGE}/fragment/history", params={k: v for k, v in params.items() if k != "change"})
    assert history.status_code == 200
    assert "data-card-error" not in history.text


async def test_a_bad_filter_in_the_address_is_a_notice(page: Any) -> None:
    doc = await page.doc(PAGE, params={"group": "bogus", "page_size": "7"})
    notes = " ".join(node.text() for node in doc.select("#editor-results .card__notice"))
    assert "A filter in the address was not valid" in notes
    assert "Showing 25 settings a page" in notes
    assert len(_keys(doc)) == 25


async def test_the_alert_and_public_site_cards_hold_their_catalog_settings(page: Any) -> None:
    doc = await page.doc(PAGE)
    for card in ("alerts", "public-site"):
        keys = {spec.key for spec in registry.settings_for(f"settings#{card}")}
        assert keys
        for key in keys:
            assert doc.select_one(f'section#{card} [data-setting-key="{key}"]') is not None, (card, key)


async def test_the_spam_dry_run_points_to_the_arm_flow(page: Any) -> None:
    doc = await page.doc(PAGE, params={"key": "spam_dry_run"})
    note = doc.select_one("#spam_dry_run .settings-item__note")
    assert note is not None
    assert note.select_one('a[href="/admin/protection#spam"]') is not None


async def test_hostile_setting_values_and_reasons_stay_text(page: Any, pages_app: Any, inert: Any) -> None:
    await pages_app.seed_all()
    await pages_app.settings(site_footer_text="Footer " + HOSTILE["img"], site_contact_name=HOSTILE["script"][:60])
    for params in ({"key": "site_footer_text"}, {}):
        response = await page.get(PAGE, params=params)
        inert(response.text, f"settings page {params}")
    history = await page.fragment("settings", "history")
    inert(history.text, "settings history")
    assert "&lt;img src=x onerror=alert(1)&gt;" in history.text
    doc = parse_html(history.text)
    row = next(r for r in doc.select("tbody tr[data-row-id]") if "site_footer_text" in r.text())
    drawer = await page.get(row.get("data-drawer-src"), htmx=True)
    assert drawer.status_code == 200
    inert(drawer.text, "settings change drawer")
    assert 'dir="auto"' in drawer.text


async def test_the_history_shows_the_apis_changes(page: Any, pages_app: Any) -> None:
    await pages_app.seed_all()
    for params in ({}, {"q": "cache_ttl"}, {"source": "admin"}, {"sort": "key", "order": "asc"}):
        api = (await page.api("GET", "settings/history", params=params)).json()
        doc = parse_html((await page.fragment("settings", "history", **params)).text)
        rows = [r.get("data-row-id") for r in doc.select("tbody tr[data-row-id]")]
        assert rows == [f"change-{item['id']}" for item in api["items"]], params
    empty = parse_html((await page.fragment("settings", "history", q="zzz-nothing")).text)
    assert "No settings changes match" in empty.text()


async def test_the_history_drawer_reverts_through_the_api_with_csrf_and_audit(page: Any, pages_app: Any) -> None:
    await pages_app.seed_all()
    api = (await page.api("GET", "settings/history", params={"q": "cache_ttl_seconds"})).json()
    newest = api["items"][0]
    drawer = parse_html((await page.fragment("settings", "history", change=newest["id"])).text)
    form = drawer.select_one("form.settings-revert")
    assert form is not None
    url = form.get("data-api-url")
    assert url == f"/admin/api/v1/settings/history/{newest['id']}/revert"
    assert set((form.get("data-refresh") or "").split()) == {"history", "editor"}
    assert (await page.api("POST", url, json={"reason": "undo"}, csrf=False)).status_code == 403
    done = await page.api("POST", url, json={"reason": "Back " + HOSTILE["img"]})
    assert done.status_code == 200, done.text
    assert pages_app.ctx.settings.int("cache_ttl_seconds") == 150
    reverts = (await page.api("GET", "audit", params={"action": "setting.revert"})).json()
    assert reverts["total"] == 1
    missing = await page.fragment("settings", "history", change=999999)
    assert "No settings change has that number" in missing.text


async def test_tables_own_requests_get_only_the_table(page: Any) -> None:
    response = await page.get(f"{PAGE}/fragment/history", htmx=True, headers={"HX-Target": "settings-history"})
    assert response.text.lstrip().startswith('<div class="dt" id="settings-history"')
    whole = await page.fragment("settings", "history")
    assert whole.text.lstrip().startswith("<section")


async def test_export_and_import_go_through_the_api(page: Any, pages_app: Any) -> None:
    doc = await page.doc(PAGE)
    card = doc.select_one("section#import-export")
    export = card.select_one("a[data-export]")
    assert export.get("href") == "/admin/api/v1/settings/export"
    form = card.select_one("form[data-settings-import]")
    assert form.get("data-preview-url") == "/admin/api/v1/settings/import/preview"
    assert form.get("data-import-url") == "/admin/api/v1/settings/import"
    exported = await page.api("GET", "settings/export")
    assert exported.status_code == 200
    document = exported.json()
    document["overrides"]["cache_ttl_seconds"] = 240
    preview = await page.api("POST", "settings/import/preview", json={"document": document})
    assert preview.status_code == 200, preview.text
    assert preview.json()["changes"] >= 1
    assert (await page.api("POST", "settings/import", json={"document": document}, csrf=False)).status_code == 403
    done = await page.api("POST", "settings/import", json={"document": document, "reason": "From the file"})
    assert done.status_code == 200, done.text
    assert pages_app.ctx.settings.int("cache_ttl_seconds") == 240
    downloads = (await page.api("GET", "audit", params={"action": "export.download"})).json()
    assert downloads["total"] >= 1


async def test_a_batch_save_needs_the_second_factor_for_admin_security(page: Any) -> None:
    editor = (await page.doc(PAGE)).select_one("[data-settings-editor]")
    assert editor.get("data-preview-url") == "/admin/api/v1/settings/preview"
    assert editor.get("data-save-url") == "/admin/api/v1/settings"
    changes = {"admin_heartbeat_interval_s": 25, "cache_ttl_seconds": 90}
    preview = (await page.api("POST", "settings/preview", json={"changes": changes})).json()
    assert preview["fresh_mfa_required"] is True
    assert preview["fresh_mfa_keys"] == ["admin_heartbeat_interval_s"]
    page.make_mfa_stale()
    stale = await page.api("PATCH", "settings", json={"changes": changes, "reason": "batch"})
    assert stale.status_code == 403
    assert stale.json()["error"]["code"] == "reauth_required"
    await page.fresh_mfa()
    saved = await page.api("PATCH", "settings", json={"changes": changes, "reason": "batch"})
    assert saved.status_code == 200, saved.text
    assert {item["key"] for item in saved.json()["changed"]} == set(changes)


async def test_the_editor_controls_save_through_the_settings_api(page: Any) -> None:
    doc = await page.doc(PAGE, params={"key": "cache_ttl_seconds"})
    control = doc.select_one('#editor-results form[data-setting-key="cache_ttl_seconds"]')
    assert control.get("data-setting-api") == "/admin/api/v1/settings/cache_ttl_seconds"
    assert control.get("data-setting-fragment").startswith("/admin/ui/setting/cache_ttl_seconds?prefix=set-editor")
    security = await page.doc(PAGE, params={"key": "admin_heartbeat_interval_s"})
    assert security.select_one('form[data-setting-key="admin_heartbeat_interval_s"][data-fresh-mfa]') is not None
    assert json.loads(control.get("data-options") or "{}") == {}
