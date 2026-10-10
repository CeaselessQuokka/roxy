"""The Live page (`/admin/live`, plan 14.1 Live row, 14.11; v1 Live Requests, row 8; parity rows 81, 82, 126 to 128):
integration tests against the real app.

What this is
    With traffic sent through the real proxy: the page, its fragments, the request drawer and the reset drawer
    answer 200 for an admin and redirect otherwise; the tail is wired to the event stream (live rows and `kpi`, with
    the replay point of the first screen) and to the request drawer; the address's filters are checked with the
    Live API's own parser; the capture card equals `GET /live/state` and carries every `live#capture` setting; the
    drawer shows a request's record, its trace and its capture, or tells "never captured" from "expired" with v1's
    texts; hostile text stays inert; bad ids never fail; the live feed reset runs only through the Data API.

Why it exists
    Plan P6 (one source of truth), the P11 page rules, and row 128 (two different "no capture" messages).

What to read next
    `roxy/admin/pages/live.py`, `tests/e2e/test_page_live.py`.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest

from roxy.admin.pages import registry
from roxy.admin.pages.testing import HOSTILE, parse_html
from roxy.core.style_guard import find_style_issues
from roxy.metrics.capture import CAPTURE_EXPIRED_MESSAGE, CAPTURE_OFF_MESSAGE

PAGE = "/admin/live"


async def _rows(page: Any, **params: Any) -> list[dict[str, Any]]:
    answer = (await page.api("GET", "live", params={"limit": 500, **params})).json()
    rows: list[dict[str, Any]] = answer["items"]
    return rows


async def _seed(pages_app: Any, **settings: Any) -> None:
    await pages_app.settings(capture_sample_served_pct=100, capture_ttl_seconds=60, **settings)
    await pages_app.seed_traffic()
    await pages_app.flush()


async def test_the_page_its_fragments_and_drawers_need_a_signed_in_admin(anon: Any) -> None:
    for path in (
        PAGE,
        f"{PAGE}/fragment/tail",
        f"{PAGE}/fragment/capture",
        f"{PAGE}/request?id=01ABCDEF",
        f"{PAGE}/reset?which=live",
    ):
        response = await anon.get(path)
        assert response.status_code == 302, path
        assert response.headers["location"] == "/admin"


async def test_every_card_the_tail_and_the_inline_settings_are_on_the_page(page: Any, pages_app: Any) -> None:
    await _seed(pages_app)
    doc = await page.doc(PAGE)
    for card in registry.cards_for("live"):
        assert doc.select_one(f"section#{card.id}[data-card]") is not None, card.id
        for spec in registry.settings_for(registry.anchor("live", card.id)):  # live_tail_buffer, capture_*
            assert doc.select_one(f'section#{card.id} [data-setting-key="{spec.key}"]') is not None, spec.key
    tail = doc.select_one("#tail [data-live-tail]")  # v1 row 8: Live Requests
    assert tail is not None
    stream = urlparse(tail.get("data-stream-url"))
    assert stream.path == "/admin/api/v1/stream"
    query = parse_qs(stream.query)
    assert query["events"] == ["live,kpi"]
    newest = await _rows(page)
    assert newest
    assert int(query["last_event_id"][0]) < min(int(r["event_id"]) for r in newest[:40])  # replays the first screen
    assert tail.get("data-detail-url") == "/admin/live/request?id={id}"
    assert doc.select_one('#tail [data-action="live-reset"][data-drawer-src="/admin/live/reset?which=live"]')
    assert doc.select_one('script[type="module"][src*="js/pages/live"]') is not None
    assert doc.select_one('link[href*="css/pages/live"]') is not None
    assert "kpi" in doc.select_one("body").get("data-stream-url", "")


async def test_filters_in_the_address_are_checked_and_handed_to_the_tail(page: Any, pages_app: Any) -> None:
    good = await page.doc(PAGE, params={"outcome": "refused", "endpoint": "games.roblox.com", "status": "4xx"})
    filters = json.loads(good.select_one("[data-live-filters]").get("data-live-filters"))
    assert filters == {"endpoint": "games.roblox.com", "outcome": "refused", "status": "4xx"}
    bad = await page.doc(PAGE, params={"outcome": "nonsense", "endpoint": "x"})
    assert json.loads(bad.select_one("[data-live-filters]").get("data-live-filters")) == {}
    assert "live filter in the address was not valid" in bad.select_one("#tail").text()


async def test_the_capture_card_equals_the_api(page: Any, pages_app: Any) -> None:
    await _seed(pages_app)
    state = (await page.api("GET", "live/state")).json()
    doc = parse_html((await page.fragment("live", "capture")).text)
    text = doc.select_one("#capture").text()
    assert "Capturing" in text
    assert f"{state['capture']['count']:,} of {state['capture']['max_records']:,} captures" in text
    assert "this worker only" in text
    await pages_app.settings(capture_enabled=0)
    off = parse_html((await page.fragment("live", "capture")).text)
    assert "Capture off" in off.select_one("#capture").text()


async def test_the_drawer_shows_the_record_the_trace_and_the_capture(page: Any, pages_app: Any) -> None:
    await _seed(pages_app)
    refused = next(r for r in await _rows(page) if r["outcome"] == "refused" and r.get("capture_id"))
    api = (await page.api("GET", f"live/{refused['request_id']}")).json()
    doc = parse_html((await page.get(f"{PAGE}/request", params={"id": refused["request_id"]})).text)
    root = doc.select_one(f'[data-live-request="{refused["request_id"]}"]')
    assert root is not None
    text = root.text()
    assert "Refused by Roxy" in text
    assert "Why did this request wait?" in text
    assert "Captured request and answer" in text
    headers = [node.text() for node in root.select(".lv-request__headers dt")]
    assert headers[: len(api["capture"]["request_headers"])] == list(api["capture"]["request_headers"])
    assert root.select_one(f'[data-copy="{refused["request_id"]}"]') is not None
    served = next(r for r in await _rows(page) if r["outcome"] == "served_upstream" and r.get("template"))
    detail = parse_html((await page.get(f"{PAGE}/request", params={"id": served["request_id"]})).text)
    link = detail.select_one('a[href^="/admin/endpoints/template?"]')
    assert link is not None and parse_qs(urlparse(link.get("href")).query)["template"] == [served["template"]]


async def test_never_captured_and_expired_are_different_messages(page: Any, pages_app: Any) -> None:
    await _seed(pages_app, capture_enabled=0)
    never = next(r for r in await _rows(page) if not r.get("capture_id"))
    doc = parse_html((await page.get(f"{PAGE}/request", params={"id": never["request_id"]})).text)
    assert "Never captured" in doc.text()
    assert CAPTURE_OFF_MESSAGE in doc.text()
    await pages_app.settings(capture_enabled=1)
    await pages_app.seed_traffic()
    captured = next(r for r in await _rows(page) if r.get("capture_id"))
    pages_app.clock.advance(61)  # past capture_ttl_seconds (60), still inside the live records' 15 minutes
    expired = parse_html((await page.get(f"{PAGE}/request", params={"id": captured["request_id"]})).text)
    assert "Capture expired" in expired.text()
    assert CAPTURE_EXPIRED_MESSAGE in expired.text()
    assert "currently 1m" in expired.text()
    gone = parse_html((await page.get(f"{PAGE}/request", params={"id": "01ZZZZZZZZZZZZZZZZZZZZZZZZ"})).text)
    assert "no longer in the live records" in gone.text()


@pytest.mark.parametrize("value", ["", "<img src=x>", "a" * 65, "../../etc", "x y"])
async def test_a_bad_request_id_says_so_in_the_drawer(page: Any, value: str) -> None:
    response = await page.get(f"{PAGE}/request", params={"id": value})
    assert response.status_code == 200
    assert "data-card-error" in response.text
    assert "request id is not valid" in response.text


@pytest.mark.parametrize(
    "params",
    [
        {"range": "forever"},
        {"status": "999,abc"},
        {"cache": "<script>"},
        {"client": "x" * 500},
        {"request": "<img>"},
        {"request": "01ABC"},
        {"which": "everything"},
    ],
    ids=lambda p: "-".join(p),
)
async def test_no_parameter_ever_fails_the_page(page: Any, pages_app: Any, params: dict[str, str]) -> None:
    await pages_app.seed_traffic()
    for path in (PAGE, f"{PAGE}/fragment/tail", f"{PAGE}/fragment/capture"):
        response = await page.get(path, params=params)
        assert response.status_code == 200, (path, params, response.text[:300])
        assert "data-card-error" not in response.text, (path, params)


async def test_hostile_text_is_inert_on_the_page_and_in_every_drawer(page: Any, pages_app: Any, inert: Any) -> None:
    await _seed(pages_app)
    await pages_app.seed_all()
    response = await page.get(PAGE)
    inert(response.text, "live page")
    assert find_style_issues(response.text, "live page") == []
    rows = await _rows(page)
    hostile = [r for r in rows if any(HOSTILE["img"] in str(r.get(k)) or "<script>" in str(r.get(k)) for k in r)]
    assert hostile, "the seeding plan sends hostile User-Agents and places"
    for row in rows:
        drawer = await page.get(f"{PAGE}/request", params={"id": row["request_id"]})
        assert drawer.status_code == 200
        inert(drawer.text, f"request {row['request_id']}")
        assert find_style_issues(drawer.text, "live request") == []
    one = parse_html((await page.get(f"{PAGE}/request", params={"id": hostile[0]["request_id"]})).text)
    assert "dir" in str(one.select_one(".caller-text").attrs)  # caller text is isolated (caller_text)
    inert((await page.get(f"{PAGE}/reset", params={"which": "live"})).text, "live reset")


async def test_the_live_reset_previews_then_runs_only_through_the_data_api(page: Any, pages_app: Any) -> None:
    await _seed(pages_app)
    assert await _rows(page)
    doc = parse_html((await page.get(f"{PAGE}/reset", params={"which": "live"})).text)
    form = doc.select_one('form[data-api-form][data-api-url="/admin/api/v1/data/resets"]')
    fields = {node.get("name"): node.get("value") for node in form.select("input[type=hidden]")}
    assert fields["families"] == "live"
    body = {"scope": "family", "families": ["live"], "preview": fields["preview"], "reason": "t", "confirm": "reset live"}
    assert (await page.api("POST", "data/resets", json=body, csrf=False)).status_code == 403
    done = await page.api("POST", "data/resets", json=body)
    assert done.status_code in (200, 202), done.text
    for _ in range(50):
        if not [r for r in await _rows(page) if r.get("event_id")]:
            break
        await pages_app.flush()
    assert not [r for r in await _rows(page) if r.get("event_id")]
    state = (await page.api("GET", "live/state")).json()
    assert state["capture"]["count"] == 0
