"""The Traffic page (`/admin/traffic`, plan 14.1 Traffic row, 14.3; v1 Traffic, Requests, Status Codes and Proxy
Timings): integration tests against the real app.

What this is
    Tests with data that went through the real proxy (`pages_app.seed_traffic()` / `seed_all()`): the page and every
    card fragment answer 200 for an admin and redirect otherwise, every registry card and every v1 key element is
    there, each number equals the admin API's answer for the same range (the page calls the same functions), a
    table request (`part=table`) answers the table alone, no control value or range ever fails the page, hostile
    text stays inert, an empty database explains itself, and the inline resets preview through the Data API and run
    only through it (CSRF, the typed phrase, the audit).

Why it exists
    Plan P6 and the P11 page rules: one source of truth per number, never a 500, caller text never markup.

What to read next
    `roxy/admin/pages/traffic.py`, `tests/e2e/test_page_traffic.py` (the same page in a browser).
"""

from __future__ import annotations

from typing import Any

import pytest

from pages_harness import PlannedRequest, parse_html
from roxy.admin.api import traffic as traffic_api
from roxy.admin.pages import registry
from roxy.core.style_guard import find_style_issues

PAGE = "/admin/traffic"
CARDS = ("requests", "bytes", "verbs", "status", "latency", "heatmap", "trends")
LAZY = ("bytes", "verbs", "status", "latency", "heatmap", "trends")
TABLE_CARDS = {"verbs": "traffic_verbs", "status": "traffic_status_sources", "latency": "traffic_latency_split"}
OUTCOME_KEYS = ("requests:served_upstream", "requests:served_cache", "requests:refused", "requests:failed")
LOCAL_KEY = "requests:answered_locally"
ONE_GET_TWO_PREFLIGHTS = (
    PlannedRequest("/games.roblox.com/v1/games?universeIds=91", "203.0.113.80"),
    PlannedRequest("/games.roblox.com/v1/games?universeIds=91", "203.0.113.81", method="OPTIONS"),
    PlannedRequest("/games.roblox.com/v1/games?universeIds=92", "203.0.113.82", method="OPTIONS"),
)
"""One request Roblox answered and two OPTIONS requests Roxy answered itself (204, reason `options_local`)."""


def _points_sum(series: dict[str, Any]) -> float:
    return sum(v for _t, v in series["points"] if isinstance(v, int | float))


def _line(key: str, values: list[int]) -> dict[str, Any]:
    return {"key": key, "label": key, "unit": "requests", "points": [[60 * i, v] for i, v in enumerate(values)]}


async def test_the_page_its_fragments_and_drawers_need_a_signed_in_admin(anon: Any) -> None:
    paths = [PAGE, f"{PAGE}/reset?which=traffic", *(f"{PAGE}/fragment/{card}" for card in CARDS)]
    for path in paths:
        response = await anon.get(path)
        assert response.status_code == 302, path
        assert response.headers["location"] == "/admin"


async def test_every_card_the_v1_elements_and_the_assets_are_on_the_page(page: Any, pages_app: Any) -> None:
    await pages_app.seed_traffic()
    doc = await page.doc(PAGE)
    for card in registry.cards_for("traffic"):
        node = doc.select_one(f"section#{card.id}[data-card]")
        assert node is not None, card.id
        if card.id in LAZY:
            assert "page-card--lazy" in node.classes(), card.id
            assert node.get("hx-get", "").startswith(f"{PAGE}/fragment/{card.id}")
    assert doc.select_one("#requests [data-chart]") is not None  # v1 row 7: Traffic (Last 60 Minutes)
    assert doc.select_one('#requests a[href="/admin/traffic?range=1h"]') is not None
    assert doc.select_one('link[href*="css/pages/traffic"]') is not None
    for card, table in TABLE_CARDS.items():  # v1 rows 3, 20, 21, 23
        fragment = parse_html((await page.fragment("traffic", card)).text)
        assert fragment.select_one(f'section#{card} [data-table="{table}"]') is not None, card
        assert fragment.select_one(f"section#{card} [data-chart]") is not None, card
        export = fragment.select_one(f'[data-table="{table}"] a[data-export][href*="format=csv"]')
        assert export is not None
        assert export.get("href").startswith("/admin/api/v1/traffic/")
    for card in ("bytes", "heatmap", "trends"):
        response = await page.fragment("traffic", card)
        assert response.status_code == 200
        assert "data-card-error" not in response.text, card
    heat = parse_html((await page.fragment("traffic", "heatmap")).text)
    assert heat.select_one("#heatmap table.heatmap__table") is not None  # the accessible table alternative
    assert len(heat.select("#heatmap tbody tr")) == 7
    for card in registry.cards_for("traffic"):
        for spec in registry.settings_for(registry.anchor("traffic", card.id)):
            assert doc.select_one(f'#{card.id} [data-setting-key="{spec.key}"]') is not None


async def test_the_requests_totals_equal_the_api_series(page: Any, pages_app: Any) -> None:
    await pages_app.seed_traffic()
    api = (await page.api("GET", "traffic/requests")).json()
    doc = await page.doc(PAGE)
    by_key = {s["key"].partition(":")[2]: _points_sum(s) for s in api["series"]}
    total = sum(by_key.values())
    assert total == len(pages_app.seeded["statuses"])
    shown = {
        node.classes().difference({"traffic-stats__item"}).pop().split("--")[1]: node.select_one(
            ".traffic-stats__number"
        ).text()
        for node in doc.select("#requests .traffic-stats__item")
    }
    assert shown["requests"] == f"{int(total):,}"
    for key, value in by_key.items():
        assert shown[key] == f"{int(value):,}", key
    chart = doc.select_one("#requests figure[data-chart]")
    assert chart is not None
    # The chart reads the same API answer by URL after the first paint (plan 6.7 page weight, gaps_latency L4).
    assert chart.get("data-series") is None
    assert chart.get("data-series-src", "").split("?")[0] == "/admin/api/v1/traffic/requests"
    assert chart.get("data-chart-stack") == "outcome"


async def test_options_answered_locally_are_their_own_line_never_served_by_roblox(page: Any, pages_app: Any) -> None:
    """Finding truth-6: the chart and its totals read the outcome measures, so the two preflights Roxy answered
    itself are "Answered by Roxy (OPTIONS)", and "Served by Roblox" is the one request that reached Roblox."""
    statuses = await pages_app.seed_traffic(list(ONE_GET_TWO_PREFLIGHTS))
    assert statuses == [200, 204, 204], statuses
    api = (await page.api("GET", "traffic/requests", params={"range": "1h", "compare": "previous"})).json()
    by_key = {s["key"]: _points_sum(s) for s in api["series"]}
    assert list(by_key) == [*OUTCOME_KEYS, LOCAL_KEY]  # stacking order
    assert by_key == {OUTCOME_KEYS[0]: 1, OUTCOME_KEYS[1]: 0, OUTCOME_KEYS[2]: 0, OUTCOME_KEYS[3]: 0, LOCAL_KEY: 2}
    # The comparison pairs line for line (its hour had no traffic: zeros, the local line included).
    assert [s["key"] for s in api["compare"]["series"]] == [*OUTCOME_KEYS, LOCAL_KEY]
    assert sum(_points_sum(s) for s in api["compare"]["series"]) == 0
    doc = await page.doc(f"{PAGE}/fragment/requests", params={"range": "1h"})
    shown = {
        node.classes().difference({"traffic-stats__item"}).pop().split("--")[1]: node
        for node in doc.select("#requests .traffic-stats__item")
    }
    number = {key: node.select_one(".traffic-stats__number").text() for key, node in shown.items()}
    assert number == {
        "requests": "3",
        "served_upstream": "1",
        "served_cache": "0",
        "refused": "0",
        "failed": "0",
        "answered_locally": "2",
    }
    local_help = shown["answered_locally"].select_one(".help-dot").get("data-help")
    assert local_help == traffic_api.ANSWERED_LOCALLY_HELP
    assert "OPTIONS" in shown["answered_locally"].text()
    summary = doc.select_one("#requests figure[data-chart] [data-chart-plot]").get("aria-label")
    assert "1 served by roblox" in summary, summary
    assert "2 OPTIONS requests Roxy answered itself" in summary, summary
    options = doc.select_one("#requests figure[data-chart]").get("data-series-options")
    assert LOCAL_KEY in options
    assert traffic_api.ANSWERED_LOCALLY_LABEL in options
    # A range without a local OPTIONS answer has no such line, and the card no such total.
    now = int(pages_app.clock.now())
    before = {"range": "custom", "from": str(now - 7200), "to": str(now - 3600)}
    quiet = (await page.api("GET", "traffic/requests", params=before)).json()
    assert [s["key"] for s in quiet["series"]] == list(OUTCOME_KEYS)
    quiet_doc = await page.doc(f"{PAGE}/fragment/requests", params=before)
    assert quiet_doc.select_one(".traffic-stats__item--answered_locally") is None


def test_the_answered_locally_line_is_in_both_periods_when_either_has_one() -> None:
    """`outcome_lines`: the local line is `requests` minus the four measures, bucket by bucket (never clamped), and
    it is in the chart and its comparison together, so the overlay pairs with it."""
    current = [
        _line("requests", [3, 1]),
        _line("served_upstream", [1, 1]),
        _line("served_cache", [0, 0]),
        _line("refused", [0, 0]),
        _line("failed", [0, 0]),
    ]
    quiet = [_line(key, [0, 0]) for key in traffic_api.OUTCOME_READS]
    lines, other = traffic_api.outcome_lines(current, quiet)
    assert [line["key"] for line in lines] == [*OUTCOME_KEYS, LOCAL_KEY]
    assert lines[-1]["points"] == [[0, 2], [60, 0]]
    assert lines[-1]["label"] == traffic_api.ANSWERED_LOCALLY_LABEL
    assert other is not None
    assert [line["key"] for line in other] == [*OUTCOME_KEYS, LOCAL_KEY]
    lines, other = traffic_api.outcome_lines(quiet, current)  # only the comparison has one
    assert [line["key"] for line in lines] == [*OUTCOME_KEYS, LOCAL_KEY]
    assert other is not None
    assert other[-1]["points"] == [[0, 2], [60, 0]]
    lines, other = traffic_api.outcome_lines(quiet)
    assert [line["key"] for line in lines] == list(OUTCOME_KEYS)
    assert other is None


async def test_status_tiles_verdict_and_table_equal_the_api(page: Any, pages_app: Any) -> None:
    await pages_app.seed_traffic()
    api = (await page.api("GET", "traffic/status/sources")).json()
    doc = parse_html((await page.fragment("traffic", "status")).text)
    for key, value in api["tiles"].items():
        tile = doc.select_one(f'#status [data-kpi="{key}"] .kpi__number')
        assert tile is not None, key
        assert tile.text() == (f"{value:,}" if value is not None else "n/a"), key
    assert api["tiles"]["roblox_429"] >= 1  # the seeding plan has a Roblox 429
    assert "Roblox is rate limiting Roxy" in doc.select_one("#status .alert").text()
    assert api["verdict"]["text"][:40] in doc.select_one("#status .alert").text()
    rows = doc.select('#status [data-table="traffic_status_sources"] tbody tr[data-row-id]')
    assert len(rows) == api["total"]
    shown = sorted(
        (r.select_one('td[data-col="source_label"]').text(), r.select_one('td[data-col="status"]').text()) for r in rows
    )
    expected = sorted((item["source_label"], str(item["status"])) for item in api["items"])
    assert shown == expected


async def test_verbs_and_latency_tables_equal_the_api(page: Any, pages_app: Any) -> None:
    await pages_app.seed_traffic()
    verbs = (await page.api("GET", "traffic/verbs/table")).json()
    doc = parse_html((await page.fragment("traffic", "verbs")).text)
    rows = doc.select('[data-table="traffic_verbs"] tbody tr[data-row-id]')
    assert len(rows) == verbs["total"] >= 1
    get = next(item for item in verbs["items"] if item["key"] == "GET")
    cell = doc.select_one('[data-table="traffic_verbs"] tbody tr td[data-col="requests"]').text()
    assert cell == f"{get['requests']:,}"
    assert doc.select_one("#verbs meter.traffic-mix__bar") is not None  # v1's method mix
    for split in ("method", "outcome", "egress", "host"):
        api = (await page.api("GET", "traffic/latency/split", params={"by": split})).json()
        fragment = parse_html((await page.fragment("traffic", "latency", split=split)).text)
        found = fragment.select('[data-table="traffic_latency_split"] tbody tr[data-row-id]')
        assert len(found) == api["total"], split
        keys = sorted(r.select_one('td[data-col="key"]').text() for r in found)
        assert keys == sorted(str(item["key"]) for item in api["items"]), split
        chart = fragment.select_one("#latency figure[data-chart]")
        assert chart is not None
        assert chart.get("data-series")
    none = parse_html((await page.fragment("traffic", "latency")).text)
    assert none.select_one('#latency select[name="split"] option[value="none"][selected]') is not None


async def test_the_heatmap_and_trends_equal_the_api(page: Any, pages_app: Any) -> None:
    await pages_app.seed_traffic()
    for metric in ("requests", "refused"):
        api = (await page.api("GET", "traffic/heatmap", params={"metric": metric})).json()
        doc = parse_html((await page.fragment("traffic", "heatmap", metric=metric)).text)
        cells = [int(c.select_one(".heat__value").text().replace(",", "")) for c in doc.select("#heatmap td.heat")]
        assert sum(cells) == sum(sum(row) for row in api["heatmap"]["cells"]), metric
    trends = (await page.api("GET", "traffic/trends")).json()
    doc = parse_html((await page.fragment("traffic", "trends")).text)
    periods = doc.select("#trends details.traffic-trend")
    assert len(periods) == len(trends["periods"]) == 3
    assert periods[0].get("open") is not None
    week = trends["periods"][0]
    first = periods[0].select("tbody tr")[0]
    assert first.select("td")[0].text() == f"{week['rows'][0]['current']:,}"


async def test_a_table_request_answers_the_table_alone(page: Any, pages_app: Any) -> None:
    await pages_app.seed_traffic()
    for card, table in TABLE_CARDS.items():
        response = await page.fragment("traffic", card, part="table", page_size=10)
        doc = parse_html(response.text)
        assert doc.select_one("section[data-card]") is None, card  # never a card inside the card
        root = doc.select_one(f'div.dt[data-table="{table}"]')
        assert root is not None, card
        assert "part=table" in root.get("data-dt-src", ""), card


@pytest.mark.parametrize(
    "params",
    [
        {"range": "forever"},
        {"range": "custom", "from": "yesterday"},
        {"range": "custom", "from": "2026-01-01T00:00:00Z", "to": "2025-01-01T00:00:00Z"},
        {"granularity": "minute", "range": "1y"},
        {"compare": "sideways"},
        {"range": "7d", "compare": "previous"},
        {"range": "all"},
        {"status_view": "bogus"},
        {"split": "<script>"},
        {"metric": "secrets"},
        {"part": "table", "page": "abc"},
        {"part": "table", "page_size": "7", "sort": "bogus", "order": "sideways"},
        {"part": "table", "q": "x" * 500},
        {"part": "table", "page": "99999999"},
    ],
    ids=lambda p: "-".join(f"{k}" for k in p),
)
async def test_no_control_value_or_range_ever_fails_the_page(page: Any, pages_app: Any, params: dict[str, str]) -> None:
    await pages_app.seed_traffic()
    for path in (PAGE, *(f"{PAGE}/fragment/{card}" for card in CARDS)):
        response = await page.get(path, params=params)
        assert response.status_code == 200, (path, params, response.text[:300])
        assert "data-card-error" not in response.text, (path, params)


async def test_hostile_text_is_inert_everywhere(page: Any, pages_app: Any, inert: Any) -> None:
    await pages_app.seed_all()
    response = await page.get(PAGE)
    inert(response.text, "traffic page")
    assert find_style_issues(response.text, "traffic page") == []
    for card in CARDS:
        fragment = await page.fragment("traffic", card)
        inert(fragment.text, f"traffic {card}")
        assert find_style_issues(fragment.text, f"traffic {card}") == []
    for split in ("host", "egress", "outcome"):
        inert((await page.fragment("traffic", "latency", split=split)).text, f"latency by {split}")
    inert((await page.get(f"{PAGE}/reset", params={"which": "traffic"})).text, "traffic reset")


async def test_an_empty_database_explains_itself(page: Any) -> None:
    doc = await page.doc(PAGE)
    assert doc.select_one("#requests .traffic-stats__item--requests .traffic-stats__number").text() == "0"
    chart = doc.select_one("#requests figure[data-chart]")
    assert "No requests in this range yet" in chart.get("data-empty-text", "")
    verbs = parse_html((await page.fragment("traffic", "verbs")).text)
    assert "No requests in this range" in verbs.text()
    assert "method mix appears once there are requests" in verbs.text()
    status = parse_html((await page.fragment("traffic", "status")).text)
    assert "No status codes in this range" in status.text()
    assert "No rate limiting in this range" in status.text()
    heat = parse_html((await page.fragment("traffic", "heatmap")).text)
    assert "every cell is empty" in heat.text()
    reset = parse_html((await page.get(f"{PAGE}/reset", params={"which": "latency"})).text)
    assert "Nothing to reset" in reset.text()


async def test_the_traffic_reset_previews_then_runs_only_through_the_data_api(page: Any, pages_app: Any) -> None:
    await pages_app.seed_traffic()
    doc = parse_html((await page.get(f"{PAGE}/reset", params={"which": "traffic"})).text)
    form = doc.select_one('form[data-api-form][data-api-url="/admin/api/v1/data/resets"]')
    assert form is not None
    fields = {node.get("name"): node.get("value") for node in form.select("input[type=hidden]")}
    assert fields["scope"] == "family"
    assert fields["families"] == "traffic"
    assert len(fields["preview"]) == 64
    assert doc.select_one('input[name="confirm"]') is not None  # a whole family: type the phrase
    assert "This will delete" in doc.text()
    body = {"scope": "family", "families": ["traffic"], "preview": fields["preview"], "reason": "test"}
    refused = await page.api("POST", "data/resets", json={**body, "confirm": "reset traffic"}, csrf=False)
    assert refused.status_code == 403
    unconfirmed = await page.api("POST", "data/resets", json=body)
    assert unconfirmed.status_code == 422
    assert unconfirmed.json()["error"]["code"] == "confirmation_required"
    done = await page.api("POST", "data/resets", json={**body, "confirm": "reset traffic"})
    assert done.status_code in (200, 202), done.text
    for _ in range(50):
        answer = (await page.api("GET", "traffic/requests")).json()
        if sum(_points_sum(s) for s in answer["series"]) == 0:
            break
        await pages_app.flush()
    assert sum(_points_sum(s) for s in answer["series"]) == 0
    after = parse_html((await page.get(PAGE)).text)
    assert after.select_one("#requests .traffic-stats__item--requests .traffic-stats__number").text() == "0"
    audit = (await page.api("GET", "audit", params={"action": "data.reset"})).json()
    assert audit["total"] >= 1


async def test_the_latency_reset_keeps_the_request_counts(page: Any, pages_app: Any) -> None:
    await pages_app.seed_traffic()
    before = (await page.api("GET", "traffic/verbs/table")).json()["items"][0]["requests"]
    doc = parse_html((await page.get(f"{PAGE}/reset", params={"which": "latency"})).text)
    digest = doc.select_one('input[name="preview"]').get("value")
    assert "Request counts are kept" in doc.text()
    body = {"scope": "family", "families": ["latency"], "preview": digest, "reason": "test", "confirm": "reset latency"}
    done = await page.api("POST", "data/resets", json=body)
    assert done.status_code in (200, 202), done.text
    for _ in range(50):
        table = (await page.api("GET", "traffic/verbs/table")).json()["items"][0]
        if table["p95_ms"] is None:
            break
        await pages_app.flush()
    assert table["requests"] == before
    assert table["p95_ms"] is None
