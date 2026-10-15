"""The development component gallery's routes and helpers (src/roxy/admin/gallery.py).

What this is
    In-process tests (httpx with an ASGI transport, no browser, no sockets) of the gallery page, its demo endpoints,
    the development-only guard, and the helpers the dashboard pages reuse (`load_glossary`, `diff_lines`),
    including where the glossary is found once roxy is installed into a release's virtualenv (a subprocess imports
    a copy of the package laid out the way deploy/deploy.sh installs it).

Why it exists
    The gallery must never exist in production (a page outside admin login), and the endpoints the browser tests
    rely on (server-side table paging, setting validation through the real catalog, the SSE stream resuming from
    Last-Event-ID, the CSRF header check) must behave exactly as the e2e tests assume.

How it works
    Each test builds a slim FastAPI app with Roxy's real SecurityHeadersMiddleware, Templates and static mount, and
    includes the gallery router directly (bypassing `include_gallery`) when testing the route guard itself.

What to read next
    src/roxy/admin/gallery.py, tests/e2e/test_design_system.py.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import APIRouter, FastAPI

from roxy.admin import gallery
from roxy.config.env import EnvSettings
from roxy.core.security_headers import SecurityHeadersMiddleware
from roxy.core.templating import STATIC_DIR, AssetHasher, HashedStaticFiles, Templates

BASE = gallery.GALLERY_PREFIX
REPO = Path(__file__).resolve().parents[3]
SRC_PACKAGE = REPO / "src" / "roxy"


def build_app(tmp_path: Path, env_name: str = "development", *, include: bool = True) -> FastAPI:
    env = EnvSettings(env=env_name, state_dir=tmp_path, site_origin="http://localhost")
    app = FastAPI()
    app.add_middleware(SecurityHeadersMiddleware)
    app.state.env = env
    hasher = AssetHasher(STATIC_DIR)
    app.state.templates = Templates(hasher=hasher)
    app.mount("/static", HashedStaticFiles(directory=STATIC_DIR, hasher=hasher), name="static")
    if include:
        app.include_router(gallery.router)
    return app


@pytest.fixture
async def client(tmp_path: Path) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=build_app(tmp_path))
    async with httpx.AsyncClient(transport=transport, base_url="http://localhost") as c:
        yield c


# ------------------------------------------------------------------------------------------- development only


async def test_gallery_answers_404_outside_development_even_when_included(tmp_path: Path) -> None:
    app = build_app(tmp_path, "production")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost") as c:
        for path in ("", "/table", "/stream", "/stats", "/chart.json"):
            response = await c.get(BASE + path)
            assert response.status_code == 404, path
        assert (await c.post(BASE + "/action", headers={"X-CSRF-Token": "x"})).status_code == 404


def test_include_gallery_adds_routes_only_in_development(tmp_path: Path) -> None:
    production = EnvSettings(env="production", state_dir=tmp_path)
    development = EnvSettings(env="development", state_dir=tmp_path)
    target = APIRouter()
    assert gallery.include_gallery(target, production) is False
    assert target.routes == []
    assert gallery.include_gallery(target, development) is True
    assert len(target.routes) == 1  # FastAPI keeps an included router as one entry


async def test_include_gallery_serves_the_page_in_development(tmp_path: Path) -> None:
    app = build_app(tmp_path, include=False)
    assert gallery.include_gallery(app, app.state.env) is True
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost") as c:
        assert (await c.get(BASE)).status_code == 200


def test_gallery_routes_are_listed_for_route_discovery() -> None:
    routes = gallery.gallery_routes()
    assert BASE in routes
    assert all(route.startswith(BASE) for route in routes)


# ------------------------------------------------------------------------------------------- the page


async def test_gallery_page_renders_every_section_under_the_page_policy(client: httpx.AsyncClient) -> None:
    response = await client.get(BASE)
    assert response.status_code == 200
    html = response.text
    for section in (
        "g-kpis",
        "g-charts",
        "g-heatmap",
        "g-table",
        "g-live",
        "g-settings",
        "g-recs",
        "g-diff",
        "g-dialogs",
        "g-empty",
        "g-feedback",
        "g-htmx",
        "g-glossary",
        "g-banners",
        "g-controls",
        "g-tokens",
    ):
        assert f'id="{section}"' in html, section
    csp = response.headers["content-security-policy"]
    nonce = csp.split("'nonce-", 1)[1].split("'", 1)[0]
    assert html.count(f'nonce="{nonce}"') == 2  # the import map and the entry module, nothing else
    assert 'id="how-to-read"' in html
    assert response.headers["cache-control"] == "no-store"  # an /admin page


@pytest.mark.parametrize("theme", ["dark", "light", "system"])
async def test_theme_query_sets_the_root_attribute(client: httpx.AsyncClient, theme: str) -> None:
    html = (await client.get(f"{BASE}?theme={theme}")).text
    assert f'<html lang="en" data-theme="{theme}"' in html


async def test_bad_theme_and_session_overrides_fall_back_to_safe_values(client: httpx.AsyncClient) -> None:
    html = (await client.get(f"{BASE}?theme=hacker&hb=99999&aw=-5")).text
    assert 'data-theme="dark"' in html
    assert 'data-heartbeat-s="600"' in html
    assert 'data-activity-window-s="1"' in html


# ------------------------------------------------------------------------------------------- table


async def test_table_fragment_sorts_filters_and_pages_on_the_server(client: httpx.AsyncClient) -> None:
    response = await client.get(f"{BASE}/table", params={"sort": "p95", "dir": "asc", "size": "10", "page": "2"})
    assert response.status_code == 200
    html = response.text
    assert "<script" not in html
    values = [int(v.replace(",", "")) for v in re.findall(r'data-col="p95"[^>]*>(?:<[^>]+>)*([\d,]+) ms', html)]
    assert values == sorted(values)
    assert len(values) == 10
    assert 'aria-sort="ascending"' in html
    assert "Page 2 of 5" in html
    filtered = (await client.get(f"{BASE}/table", params={"host": "thumbnails", "q": "icons"})).text
    assert "of <strong>3</strong>" in filtered
    clamped = (await client.get(f"{BASE}/table", params={"sort": "not_a_column", "size": "7", "page": "999"})).text
    assert 'aria-sort="descending"' in clamped
    assert "Page 5 of 5" in clamped


async def test_export_guards_spreadsheet_formulas(client: httpx.AsyncClient) -> None:
    assert gallery._csv_cell("=1+1") == "'=1+1"
    assert gallery._csv_cell("@sum") == "'@sum"
    assert gallery._csv_cell("games.roblox.com") == "games.roblox.com"
    response = await client.get(f"{BASE}/export", params={"format": "csv"})
    assert response.headers["content-type"].startswith("text/csv")
    assert response.text.splitlines()[0].startswith('"Endpoint template"')


# ------------------------------------------------------------------------------------------- setting save


async def _save(client: httpx.AsyncClient, **fields: Any) -> httpx.Response:
    return await client.post(f"{BASE}/setting", data=fields, headers={"X-CSRF-Token": "x"})


async def test_setting_save_validates_with_the_real_catalog(client: httpx.AsyncClient) -> None:
    ok = await _save(client, key="cache_ttl_seconds", value="15m", reason="test")
    assert ok.status_code == 200
    assert 'value="900"' in ok.text
    assert "Saved" in ok.text
    assert json.loads(ok.headers["hx-trigger"])["roxy:toast"]["tone"] == "ok"
    bad = await _save(client, key="cache_ttl_seconds", value="banana")
    assert bad.status_code == 422
    assert "Enter a duration" in bad.text
    assert 'value="banana"' in bad.text
    out_of_range = await _save(client, key="cache_ttl_seconds", value="2d")
    assert out_of_range.status_code == 422
    assert "86,400" in out_of_range.text


async def test_switch_posts_last_value_wins_and_high_risk_needs_reason_and_confirmation(
    client: httpx.AsyncClient,
) -> None:
    # An unchecked switch sends only the hidden "0"; a checked one sends "0" then "1".
    refused = await _save(client, key="strict_host_allowlist", value="0")
    assert refused.status_code == 422
    assert "high-risk value" in refused.text
    no_confirm = await _save(client, key="strict_host_allowlist", value="0", reason="testing")
    assert no_confirm.status_code == 422
    accepted = await _save(client, key="strict_host_allowlist", value="0", reason="testing", confirm_high_risk="1")
    assert accepted.status_code == 200
    assert "Saved" in accepted.text
    back_on = await client.post(
        f"{BASE}/setting",
        content="key=strict_host_allowlist&value=0&value=1",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert back_on.status_code == 200
    assert "checked" in back_on.text


async def test_setting_save_refuses_unknown_and_non_sample_keys(client: httpx.AsyncClient) -> None:
    assert (await _save(client, key="no_such_setting", value="1")).status_code == 404
    assert (await _save(client, key="request_deadline_s", value="60")).status_code == 404


# ------------------------------------------------------------------------------------------- actions, stream


async def test_actions_require_the_csrf_header(client: httpx.AsyncClient) -> None:
    refused = await client.post(f"{BASE}/action", data={"demo": "1"})
    assert refused.status_code == 403
    accepted = await client.post(f"{BASE}/action", data={"demo": "1"}, headers={"X-CSRF-Token": "masked"})
    assert accepted.status_code == 204
    assert "nothing changed" in json.loads(accepted.headers["hx-trigger"])["roxy:toast"]["message"]
    stats = (await client.get(f"{BASE}/stats")).json()
    assert stats["csrf_headers"][-2:] == [False, True]


async def test_heartbeat_counts_and_records_idle_time(client: httpx.AsyncClient) -> None:
    await client.post(f"{BASE}/heartbeat", json={"idle_ms": 1500})
    await client.post(f"{BASE}/heartbeat", content=b"not json")
    stats = (await client.get(f"{BASE}/stats")).json()
    assert stats["heartbeats"] == 2
    assert stats["heartbeat_idle_ms"] == [1500, None]


async def test_unauthorized_demo_answers_401(client: httpx.AsyncClient) -> None:
    assert (await client.get(f"{BASE}/unauthorized")).status_code == 401


async def test_stream_resumes_after_last_event_id(client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gallery, "EVENT_INTERVAL_S", 0)
    async with client.stream("GET", f"{BASE}/stream", headers={"Last-Event-ID": "41"}) as response:
        assert response.headers["content-type"].startswith("text/event-stream")
        body = "".join([chunk async for chunk in response.aiter_text()])
    ids = [int(line[4:]) for line in body.splitlines() if line.startswith("id: ")]
    assert ids == list(range(42, 42 + gallery.EVENTS_PER_CONNECTION))
    assert body.startswith("retry: ")
    data = [json.loads(line[6:]) for line in body.splitlines() if line.startswith("data: ")]
    assert {"id", "status", "outcome", "egress", "cache", "latency_ms", "endpoint"} <= set(data[0])
    assert all(row["client"].startswith("192.0.2.") for row in data)  # documentation addresses only (RFC 5737)
    stats = (await client.get(f"{BASE}/stats")).json()
    assert stats["last_event_ids"][-1] == "41"


async def test_palette_search_is_bounded(client: httpx.AsyncClient) -> None:
    assert (await client.get(f"{BASE}/palette", params={"q": "c"})).json() == []
    results = (await client.get(f"{BASE}/palette", params={"q": "cache"})).json()
    assert 0 < len(results) <= 20
    assert {r["group"] for r in results} <= {"Settings", "Endpoints"}


async def test_chart_spec_endpoint(client: httpx.AsyncClient) -> None:
    spec = (await client.get(f"{BASE}/chart.json")).json()
    assert len(spec["x"]) == len(spec["series"][0]["values"]) == 144


# ------------------------------------------------------------------------------------------- helpers


def test_diff_lines_marks_changes_and_folds_long_unchanged_runs() -> None:
    before = "\n".join(f"line {i}" for i in range(20))
    after = before.replace("line 10", "line ten")
    rows = gallery.diff_lines(before, after, context=2)
    ops = [row["op"] for row in rows]
    assert ops.count("delete") == 1
    assert ops.count("insert") == 1
    assert ops.count("skip") == 2
    skip = next(row for row in rows if row["op"] == "skip")
    assert skip["text"] == "6 unchanged lines"
    deleted = next(row for row in rows if row["op"] == "delete")
    assert deleted == {"op": "delete", "old": 11, "new": None, "text": "line 10"}


def test_diff_lines_does_not_fold_a_single_line() -> None:
    rows = gallery.diff_lines("a\nb\nc\nd\ne", "a\nb\nc\nd\nE", context=2)
    assert "skip" not in [row["op"] for row in rows]


def test_load_glossary_reads_entries_and_rejects_duplicates(tmp_path: Path) -> None:
    entries = gallery.load_glossary()
    assert entries["cooldown"].term == "Cooldown"
    assert "Retry-After" in entries["cooldown"].definition
    assert [e.term for e in gallery.glossary_terms(entries)][:2] == sorted(
        [e.term for e in entries.values()], key=str.lower
    )[:2]
    duplicate = tmp_path / "glossary.yml"
    duplicate.write_text(
        "terms:\n  - {id: a, term: A, definition: One.}\n  - {id: a, term: B, definition: Two.}\n", encoding="utf-8"
    )
    with pytest.raises(ValueError, match="duplicate"):
        gallery.load_glossary(duplicate)


# ------------------------------------------------------------------------------------------- glossary location


def test_glossary_is_found_in_a_release_installed_without_editable_mode(tmp_path: Path) -> None:
    """deploy/deploy.sh installs roxy into `<release>/.venv` with `uv sync --no-editable`, and `git archive` puts
    docs/ at the release root. The installed package must find docs/glossary.yml there (the first version looked
    in `.venv/lib/python3.12/docs`, so every page loading the glossary would fail in production only)."""
    release = tmp_path / "release"
    site = release / ".venv" / "lib" / "python3.12" / "site-packages"
    shutil.copytree(SRC_PACKAGE, site / "roxy", ignore=shutil.ignore_patterns("__pycache__", "vendor"))
    (release / "docs").mkdir()
    shutil.copyfile(REPO / "docs" / "glossary.yml", release / "docs" / "glossary.yml")
    code = (
        "import sys\n"
        "sys.path.insert(0, sys.argv[1])\n"
        "from roxy.admin import gallery\n"
        "assert gallery.__file__.startswith(sys.argv[1]), gallery.__file__\n"
        "print(gallery.GLOSSARY_PATH)\n"
        "print(len(gallery.load_glossary()))\n"
    )
    result = subprocess.run(
        [sys.executable, "-I", "-c", code, str(site)],
        cwd=release,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stderr[-3000:]
    path, count = result.stdout.split()
    assert Path(path) == release / "docs" / "glossary.yml"
    assert int(count) == len(gallery.load_glossary())


def test_find_glossary_takes_the_nearest_copy_at_most_five_levels_up(tmp_path: Path) -> None:
    package = tmp_path / "top" / "l4" / "l3" / "l2" / "l1" / "roxy"
    package.mkdir(parents=True)
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "glossary.yml").write_text("terms: []\n", encoding="utf-8")
    assert gallery.find_glossary(package) is None  # six levels up is too far: never an unrelated file
    top = tmp_path / "top" / "docs"
    top.mkdir()
    (top / "glossary.yml").write_text("terms: []\n", encoding="utf-8")
    assert gallery.find_glossary(package) == top / "glossary.yml"
    near = package / "docs"
    near.mkdir()
    (near / "glossary.yml").write_text("terms: []\n", encoding="utf-8")
    assert gallery.find_glossary(package) == near / "glossary.yml"  # a copy inside the package wins
    assert gallery.find_glossary() == REPO / "docs" / "glossary.yml"  # this checkout


def test_load_glossary_names_the_missing_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="glossary"):
        gallery.load_glossary(tmp_path / "docs" / "glossary.yml")
