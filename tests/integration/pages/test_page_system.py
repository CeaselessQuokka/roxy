"""The System page (`/admin/system`, plan 14.1; parity rows 3, 16, 72, 84, 85, 121, 122): integration tests.

What this is
    Tests against the real app with real data: the guards, every registry card (lazy ones through their fragments),
    the v1 promises (the workers table with Service uptime, persistence, the error log, the forced flush), the
    anchors health checks and alert emails link to (`#workers`, `#storage`, `#jobs`, `#errors`), numbers equal to the
    `GET /admin/api/v1/system/...` answers, error text a caller chose staying inert in the table and the drawer, the
    two actions going through the API with CSRF and an audit row, a table's own request getting only the table back,
    no secret in the environment or alerts cards, and no 500 for any parameter.

Why it exists
    The System page is where the owner looks when Roxy itself misbehaves; it must show the API's own numbers and
    never become the problem (plan P6, 9.16).

What to read next
    `roxy/admin/pages/system.py`, `tests/e2e/test_page_system.py`.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from roxy.admin.pages import registry
from roxy.admin.pages.testing import HOSTILE, parse_html
from roxy.core.style_guard import find_style_issues
from roxy.health.checks import SPECS as HEALTH_SPECS

PAGE = "/admin/system"
LAZY = ("jobs", "metrics-pipeline", "persistence", "alerts", "versions", "environment")
HOSTILE_SIGNATURE = "ValueError: bad path " + HOSTILE["img"]


async def _seed_errors(pages_app: Any) -> None:
    recorder = pages_app.ctx.recorder
    recorder.record_error(
        HOSTILE_SIGNATURE,
        detail="GET /games.roblox.com/" + HOSTILE["script"] + " " + HOSTILE["js_url"],
        module_line="roxy/proxy/" + HOSTILE["attr"],
        traceback="Traceback (most recent call last):\n  File " + HOSTILE["img"] + "\nValueError: " + HOSTILE["unicode"],
    )
    recorder.record_error("RuntimeError: plain one", detail="nothing hostile", source="internal")
    await pages_app.flush()


async def test_the_page_and_its_fragments_need_a_signed_in_admin(anon: Any) -> None:
    for path in (PAGE, *(f"{PAGE}/fragment/{card.id}" for card in registry.cards_for("system"))):
        response = await anon.get(path)
        assert response.status_code == 302, path
        assert response.headers["location"] == "/admin"


async def test_every_card_is_on_the_page_and_every_fragment_renders(page: Any, pages_app: Any) -> None:
    await pages_app.seed_traffic()
    await _seed_errors(pages_app)
    response = await page.get(PAGE)
    assert response.status_code == 200
    doc = parse_html(response.text)
    assert len(doc.select("h1")) == 1
    for card in registry.cards_for("system"):
        node = doc.select_one(f"section#{card.id}[data-card]")
        assert node is not None, card.id
        if card.id in LAZY:
            assert "page-card--lazy" in node.classes(), card.id
        fragment = await page.fragment("system", card.id)
        assert fragment.status_code == 200, card.id
        assert "data-card-error" not in fragment.text, (card.id, fragment.text[:400])
        assert find_style_issues(fragment.text, card.id) == []
    assert not doc.select("[data-card-error]")
    assert find_style_issues(response.text, "system page") == []
    ids = doc.ids()
    assert len(ids) == len(set(ids)), sorted({i for i in ids if ids.count(i) > 1})
    assert doc.select_one('link[href*="css/pages/system"]') is not None
    assert doc.select_one('script[type="module"][src*="js/pages/system"]') is not None


async def test_the_v1_sections_have_their_home(page: Any) -> None:
    """Plan 14.1 rows 3, 31, 34 and 37: workers with Service uptime, persistence, the error log, the flush."""
    doc = await page.doc(PAGE)
    assert doc.select_one('#fleet [data-table="workers"]') is not None
    assert doc.select_one('#fleet [data-kpi="service_uptime_s"]') is not None
    assert doc.select_one('#fleet [data-action="reset-counts"]') is not None
    assert doc.select_one('#errors [data-table="errors"]') is not None
    assert doc.select_one('#flush [data-action="flush"]') is not None
    persistence = parse_html((await page.fragment("system", "persistence")).text)
    assert persistence.select_one("section#persistence #storage table") is not None


async def test_the_anchors_health_checks_and_alerts_link_to_exist(page: Any) -> None:
    html = (await page.get(PAGE)).text
    for card in LAZY:
        html += (await page.fragment("system", card)).text
    ids = set(parse_html(html).ids())
    links = {spec.fix_link for spec in HEALTH_SPECS if spec.fix_link.startswith(f"{PAGE}#")}
    links.add(f"{PAGE}#errors")  # the error alert's "Where" (roxy.notify.notifier) and ERRORS_LINK of the rules
    assert {f"{PAGE}#workers", f"{PAGE}#storage", f"{PAGE}#jobs"} <= links
    for link in sorted(links):
        assert link.split("#", 1)[1] in ids, link


async def test_the_tables_show_the_apis_rows(page: Any, pages_app: Any) -> None:
    await _seed_errors(pages_app)
    workers = (await page.api("GET", "system/workers")).json()
    doc = parse_html((await page.fragment("system", "fleet")).text)
    rows = doc.select('[data-table="workers"] tbody tr[data-row-id]')
    assert len(rows) == workers["total"] >= 1
    assert workers["items"][0]["pid"] == int(rows[0].select_one('td[data-col="pid"]').text().split()[0])
    for params in ({}, {"q": "plain"}, {"source": "internal"}, {"sort": "count", "order": "asc"}):
        api = (await page.api("GET", "system/errors", params=params)).json()
        fragment = parse_html((await page.fragment("system", "errors", **params)).text)
        count = fragment.select_one(".dt__count").text()
        assert (f"of {api['total']:,}" in count) if api["total"] else count == "No rows", (params, count)
        shown = [row.select_one('td[data-col="signature"]').text() for row in fragment.select("tbody tr[data-row-id]")]
        assert len(shown) == len(api["items"]), params
    jobs = (await page.api("GET", "system/jobs")).json()
    jobs_doc = parse_html((await page.fragment("system", "jobs")).text)
    assert [n.select_one(".mono").text() for n in jobs_doc.select("tbody th[scope=row]")] == [
        job["name"] for job in jobs["jobs"]
    ]
    files = (await page.api("GET", "system/persistence")).json()
    persistence = parse_html((await page.fragment("system", "persistence")).text)
    assert [n.text() for n in persistence.select("#storage tbody th")] == [db["file"] for db in files["databases"]]


async def test_hostile_error_text_is_inert_in_the_table_and_the_drawer(page: Any, pages_app: Any, inert: Any) -> None:
    await _seed_errors(pages_app)
    response = await page.get(PAGE)
    inert(response.text, "system page")
    assert "&lt;img src=x onerror=alert(1)&gt;" in response.text
    doc = parse_html(response.text)
    row = next(r for r in doc.select("#errors tbody tr[data-row-id]") if HOSTILE["img"] in r.text())
    drawer_src = row.get("data-drawer-src") or ""
    assert drawer_src.startswith(f"{PAGE}/fragment/errors?")
    assert row.get("data-drawer-title") == "Error details"  # never the signature itself
    drawer = await page.get(drawer_src, htmx=True)
    assert drawer.status_code == 200
    inert(drawer.text, "error drawer")
    detail = parse_html(drawer.text)
    assert HOSTILE["img"] in detail.select_one(".system-error__signature").text()
    assert detail.select_one("pre.system-trace") is not None
    assert 'dir="auto"' in drawer.text
    assert "data-card=" not in drawer.text  # the drawer body only, never a nested card


async def test_an_unknown_or_missing_signature_says_so(page: Any) -> None:
    response = await page.fragment("system", "errors", signature="NoSuchError: nothing")
    assert response.status_code == 200
    assert "No error has that signature now" in response.text
    assert "data-card-error" in response.text


async def test_an_empty_error_log_explains_itself(page: Any) -> None:
    card = (await page.doc(PAGE)).select_one("section#errors")
    assert card is not None
    assert "No errors recorded" in card.text()
    filtered = parse_html((await page.fragment("system", "errors", q="zzz-nothing")).text)
    assert "No errors match the filter" in filtered.text()


async def test_a_tables_own_request_gets_only_the_table(page: Any) -> None:
    for card, table in (("fleet", "workers"), ("errors", "error-log")):
        response = await page.get(f"{PAGE}/fragment/{card}", htmx=True, headers={"HX-Target": table})
        assert response.status_code == 200
        assert response.text.lstrip().startswith(f'<div class="dt" id="{table}"'), (card, response.text[:120])
        assert "<section" not in response.text
        whole = await page.fragment("system", card)
        assert whole.text.lstrip().startswith("<section"), card


async def test_reset_counts_goes_through_the_api_with_csrf_and_an_audit_row(page: Any) -> None:
    doc = await page.doc(PAGE)
    form = doc.select_one("dialog#dlg-reset-counts form[data-api-form]")
    assert form is not None
    url = form.get("data-api-url")
    assert url == "/admin/api/v1/system/workers/reset-counts"
    assert form.get("data-refresh") == "fleet"
    assert (await page.api("POST", url, json={}, csrf=False)).status_code == 403
    done = await page.api("POST", url, json={"reason": "Fresh start " + HOSTILE["img"]})
    assert done.status_code == 200, done.text
    audit = (await page.api("GET", "audit", params={"action": "system.reset_counts"})).json()
    assert audit["total"] == 1
    fleet = parse_html((await page.fragment("system", "fleet")).text)
    assert fleet.select_one('td[data-col="requests"]') is not None


async def test_the_flush_form_posts_to_the_api_with_csrf(page: Any) -> None:
    form = (await page.doc(PAGE)).select_one("#flush form[data-api-form]")
    assert form is not None
    url = form.get("data-api-url")
    assert url == "/admin/api/v1/system/flush"
    assert set((form.get("data-refresh") or "").split()) == {"metrics-pipeline", "fleet"}
    assert (await page.api("POST", url, json={}, csrf=False)).status_code == 403
    done = await page.api("POST", url, json={})
    assert done.status_code == 200, done.text
    assert done.json()["flushed_here"] is True


async def test_the_inline_settings_of_the_cards_are_there(page: Any) -> None:
    for card in ("metrics-pipeline", "alerts"):
        doc = parse_html((await page.fragment("system", card)).text)
        keys = {spec.key for spec in registry.settings_for(f"system#{card}")}
        assert keys
        for key in keys:
            assert doc.select_one(f'section#{card} [data-setting-key="{key}"]') is not None, (card, key)


async def test_no_credential_value_reaches_the_environment_or_alerts(page: Any, credentials_dir: Path) -> None:
    secrets = [p.read_text(encoding="utf-8").strip() for p in credentials_dir.iterdir() if p.is_file()]
    secrets = [s for s in secrets if len(s) >= 8]
    assert secrets
    for card in ("environment", "alerts", "versions"):
        text = (await page.fragment("system", card)).text
        for secret in secrets:
            assert secret not in text, card
            assert secret[-24:] not in text, card
    env = parse_html((await page.fragment("system", "environment")).text)
    assert "never a value" in env.text()


@pytest.mark.parametrize(
    "params",
    [
        {"page": "abc"},
        {"page_size": "7"},
        {"sort": "bogus"},
        {"order": "sideways"},
        {"q": "x" * 500},
        {"source": "s" * 300},
        {"range": "forever"},
        {"signature": ""},
        {"page": "99999999"},
    ],
    ids=lambda p: "-".join(p),
)
async def test_no_filter_or_value_ever_fails_the_page(page: Any, params: dict[str, str]) -> None:
    for path in (PAGE, f"{PAGE}/fragment/errors", f"{PAGE}/fragment/fleet"):
        response = await page.get(path, params=params)
        assert response.status_code == 200, (path, params, response.text[:300])
        assert "data-card-error" not in response.text, (path, params)
