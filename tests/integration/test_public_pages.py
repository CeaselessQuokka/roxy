"""The public site end to end (plan 16.1, 9.2, 4.1 rows 12, 13, 18, 19): the real app, its lifespan and databases.

What this is
    Integration tests that start `create_app(env)` with its lifespan on temporary databases and fetch `/`,
    `/docs`, `/status`, `/robots.txt`, `/sitemap.xml`, `/favicon.ico` and `POST /csp-report` in process.

Why it exists
    The public pages are where parity (v1's SEO head and outbound links), the live settings, the strict CSP and
    the page weight budget meet. Each promise is checked on the HTML a visitor actually receives:
    `test_v1_home_links_survive` (plan 16.1), SEO parity against tests/fixtures/v1/home_page.html, live limits
    after a settings change, the status page states (from the real pause writers) and its 404 switch, CSP report
    limits, per-client shares and sampling across two app instances (two workers), the 50 KB budget, and no dash
    characters anywhere (plan C5). A worker without its user guide must refuse to start.

How it works
    The `app` and `client` fixtures (tests/conftest.py) run the full startup. Settings change through the real
    `SettingsService`; pause records come from `roxy.abuse.pause` or are written straight into control.db, and
    metrics rows straight into metrics.db, as the batch writer would. A `FakeRecorder` with the real recorder's
    signatures stands in for the metrics recorder, and one test uses the real `MetricsRecorder` end to end.

What to read next
    `roxy/public/pages.py`, `roxy/public/csp_report.py`, `roxy/templates/public/`.
"""

from __future__ import annotations

import gzip
import html
import json
import re
import sqlite3
from collections.abc import AsyncIterator
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI

from roxy.config.audit import Actor
from roxy.config.settings_service import SettingsService
from roxy.core.style_guard import assert_style_clean
from roxy.public import pages
from roxy.public.csp_report import MAX_REPORT_BYTES, SAMPLE_PER_HOUR, SOURCE_PER_HOUR

FIXTURE_HOME = Path(__file__).resolve().parents[1] / "fixtures" / "v1" / "home_page.html"
PAGES = ("/", "/docs", "/status")
BUDGET_BYTES = 50_000  # plan 16.1: under 50 KB transferred (gzip, as nginx sends it), favicon excluded
RAW_CEILING_BYTES = 120_000  # uncompressed page plus its CSS and JS: a guard against unbounded growth


# --- helpers ------------------------------------------------------------------------------------------------------


class FakeRecorder:
    """Records the calls the public pages make, with the real recorder's signatures; every other `record_*` call
    (the proxy's) is accepted and ignored."""

    def __init__(self) -> None:
        self.visits: list[tuple[str, str | None]] = []
        self.crawls: list[tuple[str, str, str | None]] = []
        self.events: list[tuple[str, str, Any, dict[str, Any]]] = []

    def record_visit(self, page: str, user_agent: str | None, *, count: int = 1, at_ms: int | None = None) -> None:
        self.visits.append((page, user_agent))

    def record_crawl(self, ip: str, path: str, user_agent: str | None = None) -> None:
        self.crawls.append((ip, path, user_agent))

    def record_event(
        self, type: str, severity: str = "info", reason: Any = None, detail: Any = None, **options: Any
    ) -> bool:
        self.events.append((type, severity, reason, dict(detail or {})))
        return True

    def __getattr__(self, name: str) -> Any:
        if name.startswith("record_"):
            return lambda *args, **kwargs: None
        raise AttributeError(name)


class Page(HTMLParser):
    """Collects what the tests inspect: head metadata, links, scripts, ids, attributes."""

    def __init__(self, text: str) -> None:
        super().__init__(convert_charrefs=True)
        self.title = ""
        self.meta: dict[str, str] = {}
        self.links: list[dict[str, str]] = []
        self.anchors: list[str] = []
        self.scripts: list[dict[str, str]] = []
        self.ld_json: list[str] = []
        self.ids: set[str] = set()
        self.styles = 0
        self.style_attributes: list[str] = []
        self.event_attributes: list[str] = []
        self._in_title = False
        self._in_ld = False
        self.feed(text)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {name: value or "" for name, value in attrs}
        if "id" in values:
            self.ids.add(values["id"])
        if "style" in values:
            self.style_attributes.append(tag)
        self.event_attributes += [name for name in values if name.startswith("on")]
        if tag == "title":
            self._in_title = True
        elif tag == "meta":
            key = values.get("name") or values.get("property")
            if key:
                self.meta[key] = values.get("content", "")
        elif tag == "link":
            self.links.append(values)
        elif tag == "a" and "href" in values:
            self.anchors.append(values["href"])
        elif tag == "script":
            self.scripts.append(values)
            self._in_ld = values.get("type") == "application/ld+json"
        elif tag == "style":
            self.styles += 1

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
        if tag == "script":
            self._in_ld = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data
        if self._in_ld:
            self.ld_json.append(data)


def link_href(page: Page, rel: str) -> str:
    return next(link["href"] for link in page.links if link.get("rel") == rel)


async def update_settings(app: FastAPI, changes: dict[str, Any]) -> None:
    ctx = app.state.ctx
    service = SettingsService(ctx.dbs.control, runtime=ctx.settings, clock=ctx.clock)
    await service.update(changes, Actor("cli", "public-pages-test"), "public pages test")
    app.state.public_status_cache = None  # the status page caches for a few seconds


def write_pause(app: FastAPI, value: Any) -> None:
    """Store a pause record (`PauseState` fields from roxy/abuse/pause.py) straight into control.db."""

    def write(conn: sqlite3.Connection) -> None:
        conn.execute(
            "INSERT INTO service_state (key, value_json, updated_at) VALUES ('pause', ?, 0) "
            "ON CONFLICT (key) DO UPDATE SET value_json = excluded.value_json",
            (json.dumps(value),),
        )

    app.state.ctx.dbs.control.write_sync(write)
    app.state.public_status_cache = None


@pytest.fixture
def recorder(app: FastAPI, client: httpx.AsyncClient) -> FakeRecorder:
    fake = FakeRecorder()
    app.state.ctx.recorder = fake
    return fake


# --- home: SEO parity and v1 links --------------------------------------------------------------------------------


async def test_home_seo_parity_with_v1(client: httpx.AsyncClient) -> None:
    v1 = Page(FIXTURE_HOME.read_text(encoding="utf-8"))
    response = await client.get("/")
    assert response.status_code == 200
    assert response.headers["content-type"] == "text/html; charset=utf-8"
    v2 = Page(response.text)
    assert v2.title == v1.title == "Roxy: Free Proxy for Roblox Web APIs"
    keys = [
        "description",
        "keywords",
        "robots",
        "theme-color",
        "og:type",
        "og:site_name",
        "og:title",
        "og:description",
        "og:url",
        "twitter:card",
        "twitter:title",
        "twitter:description",
    ]
    for key in keys:
        assert v2.meta[key] == v1.meta[key], key
    assert link_href(v2, "canonical") == link_href(v1, "canonical") == "https://roxytheproxy.com/"
    assert json.loads(v2.ld_json[0]) == json.loads(v1.ld_json[0])
    assert json.loads(v2.ld_json[0])["offers"]["price"] == "0"
    # og:image and twitter:image: an absolute https URL on the canonical origin, to an icon Roxy really serves.
    assert v2.meta["og:image"] == v2.meta["twitter:image"]
    image = v2.meta["og:image"]
    assert re.fullmatch(r"https://roxytheproxy\.com/static/public/roxy_icon\.[0-9a-f]{10}\.png", image)
    served = await client.get(image.removeprefix("https://roxytheproxy.com"))
    assert served.status_code == 200
    assert served.headers["content-type"] == "image/png"


async def test_v1_home_links_survive(client: httpx.AsyncClient) -> None:
    v1 = Page(FIXTURE_HOME.read_text(encoding="utf-8"))
    outbound = {href for href in v1.anchors if href.startswith(("http://", "https://"))}
    assert len(outbound) == 3
    home = Page((await client.get("/")).text)
    docs = Page((await client.get("/docs")).text)
    available = set(home.anchors) | set(docs.anchors)
    assert outbound <= available, outbound - available
    # v1's in-page anchors still land on a heading of the home page.
    for href in v1.anchors:
        if href.startswith("#"):
            assert href[1:] in home.ids
    assert {"titleHeader", "generalTipsHeader", "getExampleHeading", "otherMethodsHeading"} <= home.ids


async def test_internal_links_resolve(client: httpx.AsyncClient) -> None:
    docs = Page((await client.get("/docs")).text)
    for path in ("/", "/status", "/docs"):
        page = Page((await client.get(path)).text)
        for href in page.anchors:
            if href.startswith("/docs#"):
                assert href.split("#", 1)[1] in docs.ids, (path, href)
            elif href.startswith("#"):
                assert href[1:] in page.ids, (path, href)
            elif href.startswith("/#"):
                home = Page((await client.get("/")).text)
                assert href[2:] in home.ids, (path, href)


async def test_home_luau_examples_are_highlighted_and_copy_exactly(client: httpx.AsyncClient) -> None:
    text = (await client.get("/")).text
    blocks = re.findall(r'<pre tabindex="0"><code class="language-luau hl">(.*?)</code></pre>', text, re.DOTALL)
    assert len(blocks) == len(pages.HOME_EXAMPLE_NAMES)
    for block, name in zip(blocks, pages.HOME_EXAMPLE_NAMES, strict=True):
        assert '<span class="k">const</span>' in block
        # What the Copy button copies (the text content) is the checked .luau file, byte for byte.
        copied = html.unescape(re.sub(r"<[^>]+>", "", block))
        assert copied == (pages.HOME_EXAMPLES_DIR / f"{name}.luau").read_text(encoding="utf-8"), name
    # Every other code block on the home page is a URL to open in a browser, not Luau.
    for other in re.findall(r'<pre tabindex="0"><code>(.*?)</code></pre>', text, re.DOTALL):
        assert other.startswith("https://roxytheproxy.com/"), other[:80]


async def test_home_uses_details_for_collapsibles_and_site_text(client: httpx.AsyncClient) -> None:
    text = (await client.get("/")).text
    assert text.count("<details open>") >= 4
    assert "<summary><h2" in text
    assert "$10-$250 USD" in text  # site_bug_bounty_text default
    assert "FastAPI and Uvicorn" in text  # site_hosting_note default (D18 rewrite)
    assert "Python and Flask" not in text
    assert "<small>Roxy Proxy 2025-Present</small>" in text  # site_footer_text default
    assert "CeaselessQuokka" in text  # site_contact_name default


async def test_home_site_text_settings_are_live_and_escaped(app: FastAPI, client: httpx.AsyncClient) -> None:
    await update_settings(
        app,
        {
            "site_bug_bounty_text": "Rewards: <script>alert(1)</script> see [the rules](https://example.com/rules)",
            "site_footer_text": "Footer v2",
            "site_contact_name": "SomeoneElse",
        },
    )
    text = (await client.get("/")).text
    assert "<script>alert(1)</script>" not in text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in text
    assert '<a href="https://example.com/rules">the rules</a>' in text
    assert "<small>Footer v2</small>" in text
    assert "SomeoneElse" in text
    assert "SomeoneElse" in (await client.get("/docs")).text


# --- live limits --------------------------------------------------------------------------------------------------


async def test_live_limits_render_from_settings(app: FastAPI, client: httpx.AsyncClient) -> None:
    home = (await client.get("/")).text
    assert "10 requests every 50 seconds" in home
    assert "Flood limit: 300 requests per minute" in home
    assert "per experience" not in home

    await update_settings(
        app,
        {
            "allowed_requests_per_minute": 25,
            "throttle_reset_duration": 75,
            "flood_limit_per_minute": 1234,
            "place_limit_enabled": 1,
            "place_limit_per_minute": 900,
        },
    )
    home = (await client.get("/")).text
    assert "<strong>25 requests every 75 seconds</strong>" in home
    assert "one more request becomes available every 3 seconds" in home
    assert "Flood limit: 1,234 requests per minute" in home
    assert "900 requests per minute per experience" in home
    docs = (await client.get("/docs")).text
    assert "<strong>25 requests every 75 seconds</strong>" in docs
    assert "flood limit of 1,234 requests per minute" in docs
    assert "at most 900 requests per minute" in docs
    status = re.sub(r"\s+", " ", (await client.get("/status")).text)
    assert "25 requests every 75 seconds per IP address" in status

    # Owner change 2026-10-07 (D10 reversed): every request counts toward the per-IP limit, cached or not, and
    # every public page that states the limit says so and why. An admin can still switch counting off.
    readable = {
        "home": re.sub(r"\s+", " ", html.unescape(home)),
        "docs": re.sub(r"\s+", " ", html.unescape(docs)),
        "status": html.unescape(status),
    }
    for name, text in readable.items():
        assert "Every request counts toward this limit, cached or not." in text, name
        assert pages.CACHE_HITS_WHY in text, name
        assert "do not count" not in text, name
    assert "Every request counts toward your per-IP limit, cached or not (chapter 4)." in readable["docs"]  # FAQ
    assert "your own cache is the best way to stay under the limit" in readable["home"]
    assert "asking Roxy again counts even when Roxy answers from its cache" in readable["home"]
    await update_settings(app, {"throttle_window_mode": "fixed", "throttle_count_cache_hits": 0})
    home = (await client.get("/")).text
    assert "closes 75 seconds later" in home
    flat_off = re.sub(r"\s+", " ", html.unescape(home))
    assert "requests Roxy answers from its cache do not count toward this limit" in flat_off
    assert "asking Roxy again counts" not in flat_off
    assert pages.CACHE_HITS_WHY not in flat_off

    home = re.sub(r"\s+", " ", (await client.get("/")).text)
    assert "counted for each network its servers use" in home  # place_limit_key = place_prefix (default)
    await update_settings(app, {"place_limit_key": "place", "allowed_requests_per_minute": 1})
    home = re.sub(r"\s+", " ", (await client.get("/")).text)
    assert "counted for each network" not in home
    assert "shared by all of its servers" in home
    assert "<strong>1 request every 75 seconds</strong>" in home


# --- docs ---------------------------------------------------------------------------------------------------------


async def test_docs_page_renders_the_guide(client: httpx.AsyncClient) -> None:
    response = await client.get("/docs")
    assert response.status_code == 200
    page = Page(response.text)
    assert page.title == "Roxy User Guide"
    assert link_href(page, "canonical") == "https://roxytheproxy.com/docs"
    assert '<nav class="toc" aria-label="Contents">' in response.text
    assert '<a href="#4-limits">4. Limits</a>' in response.text
    assert '<h2 id="7-status-codes-and-what-to-do">' in response.text
    assert 'class="anchor" href="#12-faq"' in response.text
    assert (
        response.text.count('<pre tabindex="0"><code class="language-luau hl">') == 6
    )  # every example, colored on the server
    assert "{{" not in response.text
    assert (await client.head("/docs")).status_code == 200


async def test_startup_fails_without_the_user_guide(env: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A release that cannot find its guide must fail the deploy health gate, not serve 404 on /docs for good."""
    from roxy.main import create_app

    monkeypatch.setattr(pages, "USER_GUIDE_PATH", tmp_path / "docs" / "USER_GUIDE.md")
    app = create_app(env)
    with pytest.raises(pages.UserGuideMissing, match=r"docs/USER_GUIDE\.md was not found"):
        async with app.router.lifespan_context(app):
            pass


async def test_docs_answers_503_if_the_guide_disappears(
    app: FastAPI, client: httpx.AsyncClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Never a 404 (which the error handler would log as a probe on every visit): the fault is Roxy's."""
    monkeypatch.setattr(pages, "USER_GUIDE_PATH", tmp_path / "gone.md")
    response = await client.get("/docs")
    assert response.status_code == 503


async def test_guide_describes_refusal_bodies_as_they_are_sent(app: FastAPI, client: httpx.AsyncClient) -> None:
    """Chapter 7 says a refusal body is a JSON string; check that against a real refusal from the proxy."""
    await update_settings(app, {"tarpit_enabled": 0})  # a probe-like path is otherwise held for 8 to 20 s
    response = await client.get("/example.com/anything")
    if response.headers.get("roxy-request-id") is None:
        pytest.skip("the proxy catch-all is not installed in this build")
    assert response.status_code == 404
    assert response.headers["content-type"].startswith("application/json")
    assert isinstance(json.loads(response.content), str)
    assert response.content.endswith(b"\n")
    docs = re.sub(r"\s+", " ", (await client.get("/docs")).text)
    assert "have a JSON string as the body" in docs


# --- status -------------------------------------------------------------------------------------------------------


async def test_status_page_states(app: FastAPI, client: httpx.AsyncClient) -> None:
    text = (await client.get("/status")).text
    assert 'class="status-banner state-operational"' in text
    assert text.count('<li class="cell cell-') == pages.HOURS_SHOWN

    write_pause(app, {"paused": True, "reason": "upgrading the database", "since": 1_760_000_000})
    text = (await client.get("/status")).text
    assert 'state-paused"' in text
    assert "upgrading the database" not in text  # the admin's reason is internal

    now = int(app.state.ctx.clock.now())
    write_pause(app, {"scheduled_start": now - 60, "scheduled_end": now + 3600})
    assert 'state-maintenance"' in (await client.get("/status")).text

    write_pause(app, {})

    def failures(conn: sqlite3.Connection) -> None:
        conn.execute(
            "INSERT INTO dims (dim_hash, endpoint_template, template_version, host, method, egress, outcome, "
            "reason_code, status, source, cache_state, auth_class) VALUES (7, '/v1/games', 1, 'games.roblox.com', "
            "'GET', 'direct', 'failed', 'upstream_5xx', 502, 'roblox', 'MISS', 'anon')"
        )
        conn.execute("INSERT INTO rollup_minute (bucket_start, dim_hash, requests) VALUES (?, 7, 4321)", (now - 60,))

    app.state.ctx.dbs.metrics.write_sync(failures)
    text = (await client.get("/status")).text
    assert 'state-degraded"' in text
    assert "4321" not in text  # no counts, ever
    assert "4,321" not in text
    assert 'cell cell-degraded"' in text


async def test_status_page_reveals_no_internals(app: FastAPI, client: httpx.AsyncClient) -> None:
    text = (await client.get("/status")).text
    visible = re.sub(r"<[^>]+>", " ", text)
    assert not re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", visible)  # no IPv4 addresses
    assert app.state.ctx.worker_id not in text
    assert "leader" not in visible.lower()
    assert "Monitors can poll" in text  # the plain-language notes are there


async def test_status_page_404_when_disabled(app: FastAPI, client: httpx.AsyncClient) -> None:
    await update_settings(app, {"public_status_page_enabled": 0})
    assert (await client.get("/status")).status_code == 404
    assert (await client.head("/status")).status_code == 404
    home = (await client.get("/")).text
    assert 'href="/status"' not in home
    docs = (await client.get("/docs")).text
    assert 'href="/status"' not in docs  # the guide stops pointing visitors at a 404 (review finding 12)
    sitemap = (await client.get("/sitemap.xml")).text
    assert "/status" not in sitemap
    assert "/docs" in sitemap
    await update_settings(app, {"public_status_page_enabled": 1})
    assert (await client.get("/status")).status_code == 200
    assert 'href="/status"' in (await client.get("/docs")).text


async def test_status_page_reads_the_real_pause_writers(app: FastAPI, client: httpx.AsyncClient) -> None:
    """The page reads the record `roxy.abuse.pause` writes, and never shows the admin's reason."""
    from roxy.abuse.pause import schedule_pause, set_pause

    ctx = app.state.ctx
    actor = Actor("cli", "public-pages-test")

    async def state() -> str:
        app.state.public_status_cache = None
        text = (await client.get("/status")).text
        assert "secret internal reason" not in text
        assert "database upgrade" not in text
        found = re.search(r'class="status-banner state-([a-z]+)"', text)
        assert found is not None
        return found.group(1)

    await set_pause(ctx.dbs.control, ctx.clock, actor, paused=True, reason="secret internal reason")
    assert await state() == "paused"
    await set_pause(ctx.dbs.control, ctx.clock, actor, paused=False)
    assert await state() == "operational"
    now = int(ctx.clock.now())
    await schedule_pause(ctx.dbs.control, ctx.clock, actor, start=now - 10, end=now + 600, reason="database upgrade")
    assert await state() == "maintenance"
    await schedule_pause(ctx.dbs.control, ctx.clock, actor, start=now + 600, end=now + 1200, reason="later")
    assert await state() == "operational"


# --- crawler files and favicon ------------------------------------------------------------------------------------


async def test_robots_sitemap_favicon(client: httpx.AsyncClient) -> None:
    robots = await client.get("/robots.txt")
    assert robots.status_code == 200
    assert robots.headers["content-type"] == "text/plain; charset=utf-8"
    assert robots.content == (FIXTURE_HOME.parent / "robots.txt").read_bytes()

    sitemap = await client.get("/sitemap.xml")
    assert sitemap.headers["content-type"] == "application/xml; charset=utf-8"
    assert sitemap.content == pages.build_sitemap(pages.build_date())
    assert sitemap.text.count("<url>") == 3

    favicon = await client.get("/favicon.ico")
    assert favicon.status_code == 200
    assert favicon.headers["content-type"] == "image/png"
    assert favicon.content == pages.FAVICON_PATH.read_bytes()
    assert favicon.content.startswith(b"\x89PNG")
    assert len(favicon.content) < 16 * 1024  # v1's was 1 MB: a 100 byte request returned 10,000 times that


async def test_head_requests_are_answered(client: httpx.AsyncClient) -> None:
    for path in (*PAGES, "/robots.txt", "/sitemap.xml", "/favicon.ico"):
        response = await client.head(path)
        assert response.status_code == 200, path


# --- visits -------------------------------------------------------------------------------------------------------


async def test_visits_and_crawls_are_recorded(client: httpx.AsyncClient, recorder: FakeRecorder) -> None:
    browser = "Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0"
    await client.get("/", headers={"user-agent": browser})
    await client.get("/", headers={"user-agent": ""})
    await client.get("/docs", headers={"user-agent": "Googlebot/2.1"})
    await client.get("/status", headers={"user-agent": browser})
    await client.head("/", headers={"user-agent": browser})  # a monitor, not a visit
    await client.get("/robots.txt", headers={"user-agent": "curl/8.5.0"})
    await client.get("/sitemap.xml", headers={"user-agent": "curl/8.5.0"})
    await client.get("/favicon.ico", headers={"user-agent": browser})  # never logged (v1)
    assert recorder.visits == [
        ("home", browser),
        ("home", ""),
        ("docs", "Googlebot/2.1"),
        ("status", browser),
        ("robots", "curl/8.5.0"),
        ("sitemap", "curl/8.5.0"),
    ]
    assert recorder.crawls == [("127.0.0.1", "/robots.txt", "curl/8.5.0"), ("127.0.0.1", "/sitemap.xml", "curl/8.5.0")]


async def test_visits_and_reports_reach_the_real_metrics_recorder(app: FastAPI, client: httpx.AsyncClient) -> None:
    """The real `MetricsRecorder` classifies visitors itself and stores CSP reports as per-minute sums."""
    from roxy.metrics.recorder import MetricsRecorder

    ctx = app.state.ctx
    recorder = MetricsRecorder(ctx.dbs, ctx.settings, ctx.clock)
    ctx.recorder = recorder
    await client.get("/", headers={"user-agent": "curl/8.5.0"})
    await client.get("/docs", headers={"user-agent": "Mozilla/5.0 Firefox/131.0"})
    await client.get("/robots.txt", headers={"user-agent": "Googlebot/2.1"})
    for _ in range(2):  # the same report twice: one stored row with a count of 2
        response = await client.post(
            "/csp-report", content=json.dumps(LEGACY_REPORT), headers={"content-type": "application/csp-report"}
        )
        assert response.status_code == 204
    recorder.close()  # writes everything, including the minute still open
    rows = ctx.dbs.metrics.read_sync(lambda conn: conn.execute("SELECT type, detail_json FROM events").fetchall())
    details = [(kind, json.loads(detail)) for kind, detail in rows]
    visits = [detail for kind, detail in details if kind == "visit"]
    assert {"page": "home", "visitor": "crawler"} in visits  # the recorder writes "count" only when it is not 1
    assert any(visit["page"] == "docs" for visit in visits)
    assert any(visit["page"] == "robots" for visit in visits)
    reports = [detail for kind, detail in details if kind == "csp_report"]
    assert sum(report.get("count", 1) for report in reports) == 2
    assert len(reports) <= 2  # one row, or two if the clock crossed a minute between the posts
    assert reports[0]["directive"] == "script-src-elem"


async def test_a_failing_recorder_never_breaks_a_page(app: FastAPI, client: httpx.AsyncClient) -> None:
    class Broken:
        def record_visit(self, *args: Any) -> None:
            raise RuntimeError("recorder exploded")

        async def record_crawl(self, *args: Any) -> None:
            raise RuntimeError("recorder exploded")

    app.state.ctx.recorder = Broken()
    assert (await client.get("/")).status_code == 200
    assert (await client.get("/robots.txt")).status_code == 200


# --- strict CSP, weight budget and writing style ------------------------------------------------------------------


async def test_pages_follow_the_strict_csp(client: httpx.AsyncClient) -> None:
    for path in PAGES:
        response = await client.get(path)
        policy = response.headers["content-security-policy"]
        nonce = re.search(r"'nonce-([^']+)'", policy)
        assert nonce is not None
        assert "unsafe-inline" not in policy
        assert "unsafe-eval" not in policy
        page = Page(response.text)
        assert page.styles == 0, path
        assert page.style_attributes == [], path
        assert page.event_attributes == [], path
        assert page.scripts, path
        for script in page.scripts:
            assert script.get("nonce") == nonce.group(1), (path, script)
            if script.get("type") != "application/ld+json":  # a data block: never executed
                assert script.get("type") == "module", (path, script)
                assert script.get("src", "").startswith("/static/public/"), (path, script)
        for link in page.links:
            if link.get("rel") in ("stylesheet", "icon"):
                assert link["href"].startswith("/static/public/"), (path, link)


async def test_static_assets_are_hashed_and_immutable(client: httpx.AsyncClient) -> None:
    page = Page((await client.get("/")).text)
    css = link_href(page, "stylesheet")
    js = next(script["src"] for script in page.scripts if script.get("src"))
    for url in (css, js):
        assert re.fullmatch(r"/static/public/site\.[0-9a-f]{10}\.(css|js)", url), url
        response = await client.get(url)
        assert response.status_code == 200
        assert "immutable" in response.headers["cache-control"]
    assert "javascript" in (await client.get(js)).headers["content-type"]


def transferred(body: bytes) -> int:
    """Bytes on the wire for a body nginx compresses: gzip at nginx's default level 1 (the public server block
    sets `gzip on` for HTML, CSS and JavaScript; deploy/nginx/roxy.conf.template), or the body itself when it is
    under nginx's `gzip_min_length 1024`."""
    return len(body) if len(body) < 1024 else len(gzip.compress(body, compresslevel=1))


async def test_page_weight_budget(client: httpx.AsyncClient) -> None:
    for path in PAGES:
        response = await client.get(path)
        page = Page(response.text)
        assets = [link["href"] for link in page.links if link.get("rel") == "stylesheet"]
        assets += [script["src"] for script in page.scripts if script.get("src")]
        total, raw = transferred(response.content), len(response.content)
        for asset in assets:
            content = (await client.get(asset)).content
            total += transferred(content)
            raw += len(content)
        assert total < BUDGET_BYTES, (path, total)  # plan 16.1: under 50 KB transferred
        # A ceiling on the uncompressed size too, so a page cannot grow without bound just because it compresses
        # well (the highlighted guide is about 75 KB before compression and under 20 KB on the wire).
        assert raw < RAW_CEILING_BYTES, (path, raw)
        assert not [link for link in page.links if link.get("rel") == "preload"]
        assert "<img" not in response.text  # the only image is the favicon, which the budget excludes


async def test_no_dash_characters_in_rendered_pages(client: httpx.AsyncClient) -> None:
    for path in (*PAGES, "/robots.txt", "/sitemap.xml"):
        assert_style_clean((await client.get(path)).text, f"rendered {path}")
    for asset in ("public/site.css", "public/site.js"):
        assert_style_clean((pages.PUBLIC_STATIC_DIR.parent / asset).read_text(encoding="utf-8"), asset)


# --- POST /csp-report ---------------------------------------------------------------------------------------------

LEGACY_REPORT = {
    "csp-report": {
        "document-uri": "https://roxytheproxy.com/?q=1",
        "violated-directive": "script-src-elem",
        "effective-directive": "script-src-elem",
        "blocked-uri": "inline",
        "disposition": "enforce",
        "line-number": 4,
    }
}


async def test_csp_report_accepts_both_formats(client: httpx.AsyncClient, recorder: FakeRecorder) -> None:
    legacy = await client.post(
        "/csp-report", content=json.dumps(LEGACY_REPORT), headers={"content-type": "application/csp-report"}
    )
    assert legacy.status_code == 204
    assert legacy.content == b""
    modern = [{"type": "csp-violation", "body": {"documentURL": "https://roxytheproxy.com/docs", "blockedURL": "eval"}}]
    reports_json = await client.post(
        "/csp-report", content=json.dumps(modern), headers={"content-type": "application/reports+json"}
    )
    assert reports_json.status_code == 204
    assert [(event[0], event[1], event[2]) for event in recorder.events] == [("csp_report", "info", None)] * 2
    assert recorder.events[0][3]["document"] == "/"
    assert recorder.events[0][3]["directive"] == "script-src-elem"
    assert recorder.events[1][3]["blocked"] == "eval"


async def test_csp_report_refuses_other_content_types_sizes_and_garbage(
    app: FastAPI, client: httpx.AsyncClient, recorder: FakeRecorder
) -> None:
    await update_settings(app, {"tarpit_enabled": 0})  # the GET below reaches the proxy, which may hold a probe
    body = json.dumps(LEGACY_REPORT)
    for content_type in ("application/json", "text/plain", ""):
        response = await client.post("/csp-report", content=body, headers={"content-type": content_type})
        assert response.status_code == 415, content_type
    big = json.dumps({"csp-report": {"document-uri": "x" * MAX_REPORT_BYTES}})
    assert (
        await client.post("/csp-report", content=big, headers={"content-type": "application/csp-report"})
    ).status_code == 413

    async def chunks() -> AsyncIterator[bytes]:  # no Content-Length: the size is counted while reading
        for _ in range(10):
            yield b" " * 1024

    streamed = await client.post("/csp-report", content=chunks(), headers={"content-type": "application/csp-report"})
    assert streamed.status_code == 413
    for garbage in ("not json", "[" * 5000, "{}", '{"csp-report": 5}'):
        response = await client.post("/csp-report", content=garbage, headers={"content-type": "application/csp-report"})
        assert response.status_code == 400, garbage[:20]
    # Only POST is a report; a GET falls through to the proxy catch-all (or 405 without it), never a 204.
    assert (await client.get("/csp-report")).status_code != 204
    assert recorder.events == []


def report_body(line: int, document: str = "https://roxytheproxy.com/") -> str:
    """A legacy report whose line number makes it distinct from every other line number."""
    return json.dumps(
        {"csp-report": dict(LEGACY_REPORT["csp-report"], **{"line-number": line, "document-uri": document})}
    )


def client_from(app: FastAPI, ip: str) -> httpx.AsyncClient:
    """A client whose requests arrive from `ip` (the socket peer; no trusted proxy in between)."""
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=(ip, 50001)), base_url="http://testserver")


async def test_csp_report_one_client_cannot_spend_the_budget(
    app: FastAPI, client: httpx.AsyncClient, recorder: FakeRecorder
) -> None:
    """Review finding 2: 10 bodies of 10 distinct reports from one IP used to fill all 100 slots of the hour."""
    hour_at_start = int(app.state.ctx.clock.now() // 3600)
    for request in range(10):
        reports = [
            {
                "type": "csp-violation",
                "body": {"documentURL": "https://roxytheproxy.com/", "lineNumber": request * 10 + i},
            }
            for i in range(10)
        ]
        response = await client.post(
            "/csp-report", content=json.dumps(reports), headers={"content-type": "application/reports+json"}
        )
        assert response.status_code == 204  # the answer never says whether the report was kept
    attacker = len(recorder.events)
    async with client_from(app, "198.51.100.7") as genuine_browser:
        response = await genuine_browser.post(
            "/csp-report",
            content=report_body(99, "https://roxytheproxy.com/admin"),
            headers={"content-type": "application/csp-report"},
        )
    assert response.status_code == 204
    if int(app.state.ctx.clock.now() // 3600) != hour_at_start:
        pytest.skip("the test ran across a clock hour, which legitimately opens a new report budget")
    assert attacker == SOURCE_PER_HOUR
    assert all(event[3].get("others_in_body") == 9 for event in recorder.events[:attacker])  # one slot per body
    assert recorder.events[-1][3]["document"] == "/admin"  # the genuine report was kept


async def test_csp_report_sampling_holds_across_two_workers(app: FastAPI, client: httpx.AsyncClient, env: Any) -> None:
    from roxy.main import create_app

    first = FakeRecorder()
    app.state.ctx.recorder = first
    hour_at_start = int(app.state.ctx.clock.now() // 3600)
    other_app = create_app(env)  # a second "worker" sharing the same databases
    headers = {"content-type": "application/csp-report"}
    async with other_app.router.lifespan_context(other_app):
        second = FakeRecorder()
        other_app.state.ctx.recorder = second
        # 2 workers x 12 client networks x 5 distinct reports = 120 reports, each within every per-client and
        # per-report share, so only the fleet-wide budget of 100 can stop them.
        for worker, target in enumerate((app, other_app)):
            for network in range(12):
                async with client_from(target, f"192.0.2.{worker * 50 + network}") as browser:
                    for line in range(SOURCE_PER_HOUR):
                        body = report_body(worker * 10_000 + network * 100 + line)
                        assert (await browser.post("/csp-report", content=body, headers=headers)).status_code == 204
    if int(app.state.ctx.clock.now() // 3600) != hour_at_start:
        pytest.skip("the test ran across a clock hour, which legitimately opens a new report budget")
    assert len(first.events) + len(second.events) == SAMPLE_PER_HOUR
    assert first.events
    assert second.events
