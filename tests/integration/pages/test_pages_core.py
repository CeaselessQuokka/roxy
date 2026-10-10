"""The dashboard pages core (P11): registry, routes and guards, the shell context, conventions and static rules.

What this is
    Integration tests against the real app (`pages_app`, a signed-in `page`): the registry of the 18 pages and the
    v1 section map, the pages router (every page answers, guarded like the API, unbuilt pages say "coming soon",
    `/admin/dashboard` is the Overview), the shell (navigation from the registry, theme and density from the
    admin's preferences, the time range from the URL, banners with the live caller texts, the bell, the palette's
    LLM export actions and server search), the inline setting fragment, the kit's conventions (a failing card
    renders in place, a bad table query never fails a page), the glossary loaded at startup, template warming, and
    the CSP and writing-style rules on every template and script of the dashboard.

Why it exists
    Seven builders build on these pieces at the same time; each rule here is one they rely on without testing it
    again on every page.

What to read next
    `roxy/admin/pages/*.py`, `tests/integration/pages/test_page_audit.py` (the reference page),
    `.remake/P11_CONTRACT.md`.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
from fastapi.routing import iter_route_contexts

from roxy.admin.api.recommendations import _counts
from roxy.admin.pages import kit, registry, shell
from roxy.admin.pages.registry import PAGES, SHELL_PAGE, V1_SECTIONS
from roxy.admin.pages.testing import HOSTILE, assert_inert, parse_html, seed_recommendation
from roxy.config.catalog import CATALOG, NON_PAGE_HOMES
from roxy.config.catalog import PAGES as CATALOG_PAGES
from roxy.core.style_guard import find_style_issues
from roxy.insights import read_recommendations

REPO = Path(__file__).resolve().parents[3]
TEMPLATES = REPO / "src" / "roxy" / "templates"
STATIC = REPO / "src" / "roxy" / "static"


# ============================================================================================ registry


def test_the_registry_has_the_18_pages_of_plan_14_1_in_the_catalog_vocabulary() -> None:
    assert sorted(p.id for p in PAGES) == sorted(CATALOG_PAGES)
    for spec in PAGES:
        assert spec.purpose.endswith("."), spec.id
        assert spec.how_to_read, spec.id
        assert all(len(p) > 40 for p in spec.how_to_read), spec.id
        assert spec.cards, spec.id
        ids = [c.id for c in registry.cards_for(spec.id)]
        assert len(ids) == len(set(ids)), spec.id
        assert (
            find_style_issues(
                " ".join([spec.purpose, *spec.how_to_read, *(c.title + " " + c.help for c in spec.cards)])
            )
            == []
        )


def test_every_catalog_anchor_is_a_registry_card_or_a_non_page_home() -> None:
    assert registry.unplaced_anchors() == []
    for spec in CATALOG.values():
        for anchor in spec.pages:
            assert anchor in NON_PAGE_HOMES or anchor in registry.page_anchors(), (spec.key, anchor)


def test_the_v1_section_map_has_37_rows_with_unique_tests_and_known_cards() -> None:
    assert [row.row for row in V1_SECTIONS] == list(range(1, 38))
    names = [row.test for row in V1_SECTIONS]
    assert len(names) == len(set(names))
    root = parse_html("<div></div>")
    for row in V1_SECTIONS:
        assert re.fullmatch(r"[a-z0-9_]+", row.test), row.test
        for check in row.checks:
            if check.page == SHELL_PAGE:
                root.select(check.card)  # a valid selector
            else:
                assert check.card in [c.id for c in registry.cards_for(check.page)], (row.row, check)
            for selector in check.selectors:
                root.select(selector)  # every key element is a selector the harness can read
                key = re.search(r'data-setting-key="([a-z0-9_]+)"', selector)
                if key:
                    assert key.group(1) in CATALOG, selector


def test_navigation_model_lists_every_page_once_with_help_last() -> None:
    model = registry.nav_model()
    ids = [item["id"] for item in model["pages"]]
    assert ids == [p.id for p in PAGES if p.group != registry.HELP_GROUP] + ["help"]
    assert {group["id"] for group in model["groups"]} == {g for g, _ in registry.NAV_GROUPS}


# ============================================================================================ routes and guards


def test_the_pages_router_passes_the_mount_checks_and_covers_every_page(pages_app: Any) -> None:
    from roxy.admin import pages as pages_package
    from roxy.admin.router import check_page_router

    check_page_router("roxy.admin.pages", pages_package.router)
    paths = {str(c.path) for c in iter_route_contexts(pages_app.app.router.routes)}
    for spec in PAGES:
        assert spec.href in paths, spec.id
    assert "/admin/dashboard" in paths
    for context in iter_route_contexts(pages_package.router.routes):
        assert set(context.methods or ()) <= {"GET", "HEAD"}, context.path  # page routes are read-only


async def test_signed_out_pages_redirect_to_the_login_and_unknown_paths_stay_404(anon: Any) -> None:
    for path in (
        "/admin/audit",
        "/admin/overview",
        "/admin/dashboard",
        "/admin/audit/fragment/log",
        "/admin/ui/palette?q=cache",
        "/admin/ui/setting/cache_ttl_seconds",
        "/admin/ui/status",
    ):
        response = await anon.get(path)
        assert response.status_code == 302, path
        assert response.headers["location"] == "/admin", path
    missing = await anon.get("/admin/no-such-page")
    assert missing.status_code == 404


async def test_a_wrong_method_on_a_page_is_404_signed_out_and_405_for_an_admin(anon: Any, page: Any) -> None:
    signed_out = await anon.http.post("/admin/audit", headers=anon.owner.harness.headers())
    assert signed_out.status_code == 404
    signed_in = await page.http.post("/admin/audit", headers=page.owner.harness.headers())
    assert signed_in.status_code == 405
    assert "GET" in signed_in.headers["allow"]


async def test_dashboard_is_the_overview_and_the_login_lands_there(page: Any) -> None:
    doc = await page.doc("/admin/dashboard")
    assert doc.select_one("body").get("data-page") == "overview"
    assert doc.select_one("h1").text() == "Overview"
    login = await page.get("/admin")
    assert login.status_code == 302
    assert login.headers["location"] == "/admin/dashboard"


# The ids are "page_<id>", never a bare "live": the root conftest skips tests with a "live" keyword.
@pytest.mark.parametrize("page_id", [p.id for p in PAGES], ids=lambda p: f"page_{p}")
async def test_every_page_renders_the_shell_with_its_purpose_and_how_to_read(page: Any, page_id: str) -> None:
    response = await page.get(f"/admin/{page_id}")
    assert response.status_code == 200, response.text[:500]
    html = response.text
    doc = parse_html(html)
    assert len(doc.select("h1")) == 1
    assert doc.select_one("main#main") is not None
    assert doc.select_one("body").get("data-page") == page_id
    spec = registry.page(page_id)
    assert spec.purpose in " ".join(doc.select_one(".page-header__purpose").text().split())
    assert doc.select_one("details#how-to-read") is not None
    assert not doc.select("[data-card-error]"), [n.text()[:200] for n in doc.select("[data-card-error]")]
    assert not re.search(r"\sstyle\s*=", html)
    assert not re.search(r"\son[a-z]+\s*=\s*[\"']", html)
    for tag in re.findall(r"<script\b[^>]*>", html):
        assert "nonce=" in tag, tag
    assert find_style_issues(html, page_id) == []
    assert_inert(html, page_id)
    if not registry.is_built(page_id):
        assert doc.select_one("[data-coming-soon]") is not None


# ============================================================================================ the shell


async def test_the_sidebar_phone_menu_and_palette_list_the_registry(page: Any) -> None:
    doc = await page.doc("/admin/audit")
    sidebar = [a.get("data-nav-id") for a in doc.select("#sidebar .nav-link")]
    assert sidebar == [p.id for p in PAGES if p.id != "help"] + ["help"]
    sheet = {a.get("href") for a in doc.select("#nav-sheet a.sheet__link")}
    assert sheet == {p.href for p in PAGES}
    palette = {li.get("data-href") for li in doc.select("#palette-list [data-group=Pages]")}
    assert palette == {p.href for p in PAGES}
    current = doc.select_one('#sidebar a[aria-current="page"]')
    assert current is not None
    assert current.get("href") == "/admin/audit"


async def test_the_palette_offers_the_llm_export_and_a_json_health_run(page: Any) -> None:
    doc = await page.doc("/admin/audit")
    copy = doc.select_one("#pal-act-llm-copy")
    assert copy.get("data-action") == "llm-copy"
    assert copy.get("data-url") == "/admin/api/v1/export/llm?format=text"
    assert doc.select_one("#pal-act-llm-json").get("data-url") == "/admin/api/v1/export/llm?download=true"
    assert doc.select_one("#pal-act-llm-schema").get("data-href") == "/admin/api/v1/export/llm/schema"
    health = doc.select_one("#pal-act-health")
    assert health.get("data-post-json") == "/admin/api/v1/health/runs"
    assert health.get("data-json-body") == '{"include_credential": false}'
    exported = await page.api("GET", "export/llm", params={"format": "text"})
    assert exported.status_code == 200
    assert (await page.api("GET", "export/llm/schema")).status_code == 200


async def test_the_shell_urls_csrf_session_and_stream(page: Any) -> None:
    doc = await page.doc("/admin/audit")
    body = doc.select_one("body")
    assert body.get("data-prefs-url") == "/admin/api/v1/prefs"
    assert body.get("data-status-url") == "/admin/ui/status"
    assert body.get("data-status-sig") == "p0t0"
    assert body.get("data-heartbeat-url") == "/admin/api/v1/auth/heartbeat"
    assert body.get("data-stream-url").startswith("/admin/api/v1/stream?events=settings_changed")
    token = doc.select_one('meta[name="csrf-token"]').get("content")
    assert token
    assert len(token) > 40
    again = (await page.doc("/admin/audit")).select_one('meta[name="csrf-token"]').get("content")
    assert again != token  # masked afresh per response (BREACH, plan 9.6)


async def test_theme_and_density_come_from_the_admins_preferences(page: Any) -> None:
    doc = await page.doc("/admin/audit")
    assert doc.select_one("html").get("data-theme") == "dark"
    saved = await page.api("POST", "prefs", json={"theme": "light", "density": "dense"})
    assert saved.status_code == 200
    doc = await page.doc("/admin/audit")
    assert doc.select_one("html").get("data-theme") == "light"
    assert doc.select_one("html").get("data-density") == "dense"


async def test_the_time_range_comes_from_the_url_and_a_bad_one_is_a_notice(page: Any) -> None:
    doc = await page.doc("/admin/overview", params={"range": "7d", "compare": "previous"})
    assert doc.select_one('input[name="range"][value="7d"]').get("checked") is not None
    assert doc.select_one('input[name="compare"][value="previous"]').get("checked") is not None
    assert doc.select_one(".range__long").text() == "Last 7 days"
    bad = await page.doc("/admin/overview", params={"range": "forever", "compare": "nope"})
    notice = bad.select_one(".page-notice")
    assert notice is not None
    assert "not valid" in notice.text()
    custom = await page.doc(
        "/admin/overview", params={"range": "custom", "from": "2026-10-01T00:00", "to": "2026-10-02T00:00"}
    )
    assert custom.select_one(".page-notice") is None
    unbounded = await page.get("/admin/overview", params={"range": "custom", "from": "x" * 500})
    assert unbounded.status_code == 200


def test_resolve_time_follows_the_api_rules() -> None:
    time = shell.resolve_time({"range": "6h", "compare": "week"}, now=1_800_000_000, tz="UTC")
    assert time.tr.key == "6h"
    assert time.tr.compare == "week"
    assert time.params == {"range": "6h", "compare": "week"}
    assert time.query(page=2) == "range=6h&compare=week&page=2"
    fallback = shell.resolve_time({"range": "6h", "from": "1"}, now=1_800_000_000, tz="UTC")
    assert fallback.notice
    assert fallback.tr.key == "24h"
    preferred = shell.resolve_time({}, now=1_800_000_000, tz="UTC", default_range="30d", default_compare="previous")
    assert preferred.tr.key == "30d"
    assert preferred.params == {"range": "30d", "compare": "previous"}


async def test_banners_and_dialogs_say_what_callers_get_from_the_live_setting(page: Any, pages_app: Any) -> None:
    await pages_app.settings(pause_message_default="Back after the upgrade.")
    paused = await page.api("POST", "protection/pause", json={"paused": True, "message": ""})
    assert paused.status_code == 200, paused.text
    doc = await page.doc("/admin/audit")
    banner = doc.select_one(".banner--bad")
    assert banner is not None
    assert "Back after the upgrade." in banner.text()
    assert doc.select_one("body").get("data-status-sig") == "p1t0"
    status = await page.get("/admin/ui/status")
    assert status.json() == {"paused": True, "throttle_all": False, "signature": "p1t0"}
    dialog = doc.select_one("#dlg-pause form")
    assert dialog.get("data-api-url") == "/admin/api/v1/protection/pause"
    assert dialog.select_one('input[name="paused"]').get("value") == "false"
    resumed = await page.api("POST", "protection/pause", json={"paused": False})
    assert resumed.status_code == 200
    doc = await page.doc("/admin/audit")
    pause_form = doc.select_one("#dlg-pause form")
    assert pause_form.select_one('input[name="paused"]').get("data-json") == "bool"
    assert pause_form.select_one("#dlg-pause-message").get("placeholder") == "Back after the upgrade."
    # The pause dialog is the home of pause_message_default (plan 15.6): its inline editor sits next to the form.
    assert doc.select_one('#dlg-pause [data-setting-key="pause_message_default"][data-setting-api]') is not None
    assert doc.select_one('#dlg-throttle-all [data-setting-key="global_throttle_limit"] input[name=limit]') is not None


async def test_a_dashed_pause_message_is_a_422_on_the_field(page: Any) -> None:
    dash = chr(0x2014)
    response = await page.api("POST", "protection/pause", json={"paused": True, "message": f"Back soon {dash} sorry"})
    assert response.status_code == 422
    assert "message" in response.json()["error"]["fields"]


async def test_the_bell_counts_the_same_rows_as_the_recommendations_api(page: Any, pages_app: Any) -> None:
    await seed_recommendation(pages_app.ctx, pages_app.clock, severity="critical")
    await seed_recommendation(pages_app.ctx, pages_app.clock, severity="warn")
    facets = await pages_app.ctx.dbs.metrics.read(read_recommendations.facets)
    api_counts = _counts(facets)
    assert shell.bell_counts(facets)["open"] == api_counts["open"] == 2
    assert shell.bell_counts(facets)["critical"] == api_counts["open_by_severity"]["critical"] == 1
    doc = await page.doc("/admin/audit")
    assert doc.select_one(".topbar__recs").get("aria-label") == "Recommendations: 2 open, 1 critical"


async def test_preferences_dialog_holds_the_user_menu_settings_and_the_admins_own_choices(page: Any) -> None:
    doc = await page.doc("/admin/audit")
    dialog = doc.select_one("dialog#preferences")
    keys = {node.get("data-setting-key") for node in dialog.select("[data-setting-key]")}
    assert keys == {"ui_timezone", "ui_default_theme"}
    form = dialog.select_one("form[data-api-form]")
    assert form.get("data-api-url") == "/admin/api/v1/prefs"
    assert {n.get("name") for n in form.select("[name]")} == {"default_range", "compare", "timezone"}


# ============================================================================================ glossary and warming


def test_the_glossary_and_the_warmed_templates_are_loaded_at_startup(pages_app: Any) -> None:
    glossary = getattr(pages_app.app.state, shell.GLOSSARY_STATE)
    assert len(glossary) > 50
    warmed = pages_app.app.state.admin_templates_warmed
    assert warmed["templates"] > 30


async def test_a_missing_glossary_fails_the_startup(monkeypatch: pytest.MonkeyPatch) -> None:
    from types import SimpleNamespace

    from roxy.admin import pages as pages_package

    def missing() -> Any:
        raise FileNotFoundError("the dashboard glossary docs/glossary.yml does not exist")

    monkeypatch.setattr(shell, "load_glossary", missing)
    app = SimpleNamespace(state=SimpleNamespace())
    with pytest.raises(FileNotFoundError, match="glossary"):
        async with pages_package.dashboard_lifespan(app):
            pass


# ============================================================================================ inline settings, palette


async def test_the_inline_setting_fragment_renders_one_control_in_api_mode(page: Any) -> None:
    response = await page.get("/admin/ui/setting/cache_ttl_seconds", params={"prefix": "set-settings", "saved": 1})
    assert response.status_code == 200
    doc = parse_html(response.text)
    form = doc.select_one("form#set-settings-cache_ttl_seconds")
    assert form.get("data-setting-api") == "/admin/api/v1/settings/cache_ttl_seconds"
    assert form.get("data-setting-fragment") == "/admin/ui/setting/cache_ttl_seconds?prefix=set-settings"
    assert form.get("hx-post") is None
    assert doc.select_one(".setting__saved") is not None
    assert (await page.get("/admin/ui/setting/no_such_setting")).status_code == 404
    odd = await page.get("/admin/ui/setting/cache_ttl_seconds", params={"prefix": '"><img src=x>'})
    assert odd.status_code == 200
    assert 'id="set-cache_ttl_seconds"' in odd.text
    risky = parse_html((await page.get("/admin/ui/setting/strict_host_allowlist")).text)
    assert risky.select_one("form").get("data-always-risky") is not None
    fresh = parse_html((await page.get("/admin/ui/setting/admin_reauth_window_s")).text)
    assert fresh.select_one("form").get("data-fresh-mfa") is not None


async def test_palette_search_answers_settings_recommendations_and_endpoints_as_admin_paths(
    page: Any, pages_app: Any
) -> None:
    await pages_app.seed_traffic()
    await seed_recommendation(pages_app.ctx, pages_app.clock)
    assert (await page.get("/admin/ui/palette", params={"q": "c"})).json() == []
    results = (await page.get("/admin/ui/palette", params={"q": "cache"})).json()
    assert 0 < len(results) <= 20
    assert all(r["href"].startswith("/admin/") for r in results)
    groups = {r["group"] for r in results}
    assert "Settings" in groups
    games = (await page.get("/admin/ui/palette", params={"q": "games.roblox"})).json()
    assert any(r["group"] == "Endpoints" for r in games)
    hostile = (await page.get("/admin/ui/palette", params={"q": "refuses"})).json()
    assert any(r["group"] == "Recommendations" and HOSTILE["script"] in r["label"] for r in hostile)


# ============================================================================================ kit conventions


async def test_a_failing_card_renders_in_place_and_the_page_keeps_working(page: Any, pages_app: Any) -> None:
    probe = kit.Page("help")

    @probe.card("guide")
    async def broken(view: kit.PageView) -> dict[str, Any]:
        raise RuntimeError("boom")

    @probe.card("glossary")
    async def refused(view: kit.PageView) -> dict[str, Any]:
        from roxy.admin.api.common import unavailable

        raise unavailable("The metrics database is busy right now; try again shortly.")

    pages_app.app.include_router(probe.router)
    failed = await page.fragment("help", "guide")
    assert failed.status_code == 200
    assert "data-card-error" in failed.text
    assert "failed to load" in failed.text
    assert "boom" not in failed.text
    busy = await page.fragment("help", "glossary")
    assert "The metrics database is busy" in busy.text
    assert (await page.fragment("help", "no-such-card")).status_code == 404


def test_table_query_never_fails_a_page() -> None:
    from roxy.admin.api.audit import AUDIT_TABLE

    class View:
        class request:
            query_params = {"page": "abc", "page_size": "7", "sort": "bogus", "order": "sideways", "q": "x"}

            class url:
                path = "/admin/audit"

    tq, notice = kit.table_query(View(), AUDIT_TABLE)  # type: ignore[arg-type]
    assert (tq.page, tq.page_size, tq.sort, tq.order) == (1, 25, "id", "desc")
    assert notice
    assert "not valid" in notice
    # A second table on the page ignores the address (it belongs to the main table) except in its own fragment.
    View.request.query_params = {"q": "x", "page": "2"}
    second, quiet = kit.table_query(View(), AUDIT_TABLE, address=False)  # type: ignore[arg-type]
    assert (second.q, second.page, quiet) == ("", 1, None)
    main, _ = kit.table_query(View(), AUDIT_TABLE)  # type: ignore[arg-type]
    assert (main.q, main.page) == ("x", 2)
    View.request.url.path = "/admin/audit/fragment/other"
    own, _ = kit.table_query(View(), AUDIT_TABLE, address=False)  # type: ignore[arg-type]
    assert (own.q, own.page) == ("x", 2)


# ============================================================================================ static rules


def _dashboard_templates() -> list[Path]:
    return sorted((TEMPLATES / "admin").rglob("*.html")) + sorted((TEMPLATES / "components").glob("*.html"))


def _dashboard_scripts() -> list[Path]:
    return sorted(p for p in (STATIC / "js").rglob("*.js") if p.name != "auth.js")


@pytest.mark.parametrize("path", _dashboard_templates(), ids=lambda p: str(p.relative_to(TEMPLATES)))
def test_dashboard_templates_keep_the_csp_rules(path: Path) -> None:
    markup = re.sub(r"\{#.*?#\}", "", path.read_text(encoding="utf-8"), flags=re.DOTALL)
    assert not re.search(r"\sstyle\s*=", markup)
    assert not re.search(r"\son[a-z]+\s*=", markup)
    assert "javascript:" not in markup.lower()
    assert "|safe" not in markup.replace(" ", "")
    for tag in re.findall(r"<script\b[^>]*>", markup):
        assert 'nonce="{{ csp_nonce }}"' in tag, tag
    fragment = "components" in path.parts or "pages" in path.parts  # card and fragment templates (plan 9.2)
    if fragment:
        assert "<script" not in markup.lower(), path


FORBIDDEN_JS = {
    r"\beval\s*\(": "eval",
    r"new\s+Function\b": "new Function",
    r"\.innerHTML\b": "innerHTML",
    r"\.outerHTML\s*=": "outerHTML assignment",
    r"insertAdjacentHTML": "insertAdjacentHTML",
    r"document\.write": "document.write",
    r"setAttribute\(\s*[\"']style[\"']": "style attribute",
    r"\.cssText\b": "cssText",
    r"set(?:Timeout|Interval)\(\s*[\"'`]": "timer with a code string",
    r"https?://(?!www\.w3\.org/2000/svg)": "absolute URL",
}


@pytest.mark.parametrize("path", _dashboard_scripts(), ids=lambda p: str(p.relative_to(STATIC)))
def test_dashboard_scripts_never_evaluate_strings_or_write_html(path: Path) -> None:
    code = re.sub(r"/\*.*?\*/", "", path.read_text(encoding="utf-8"), flags=re.DOTALL)
    code = re.sub(r"(?m)^\s*//.*$", "", code)
    assert [label for pattern, label in FORBIDDEN_JS.items() if re.search(pattern, code)] == []


def test_every_core_module_is_in_the_import_map() -> None:
    base = (TEMPLATES / "admin" / "base.html").read_text(encoding="utf-8")
    for path in (STATIC / "js").glob("*.js"):
        if path.name == "auth.js":
            continue
        assert f'"{path.stem}"' in base, f"{path.name} is missing from MODULES in base.html"


@pytest.mark.parametrize(
    "path",
    [*_dashboard_templates(), *_dashboard_scripts(), *sorted((STATIC / "css").rglob("*.css"))],
    ids=lambda p: p.name,
)
def test_dashboard_sources_pass_the_writing_style_check(path: Path) -> None:
    assert find_style_issues(path.read_text(encoding="utf-8"), str(path)) == []
