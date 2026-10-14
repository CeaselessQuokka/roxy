"""P11 adversarial review, lens "honest numbers" (plan P6 and 6.8): reproductions, regression tests since the fixes.

What this is
    One test per finding of `.remake/p11_review/find_truth.md` (ids `truth-<n>`). Each test drives the real app in
    process (the fixtures of `tests/integration/pages/conftest.py`: real proxy, real login, real read models), works
    out the expected number by hand from the traffic it seeded, and compares it with what the admin API answers and
    what the dashboard page renders. Each was marked `xfail(strict=True)` with its finding id until the P11 review
    round fixed it (a comment above each test names the fix); each is a regression test now.

Why it exists
    Plan P6: "Metrics never flatter", and plan 6.8: a comparison over a reset shows a notice, never a misleading
    delta. The page tests check that a page equals its API; these check that both equal the truth.

What to read next
    `roxy/metrics/queries.py` (windows, comparisons, deltas), `roxy/admin/api/overview.py`,
    `tests/integration/pages/test_page_overview.py`.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any
from zoneinfo import ZoneInfo

import pytest

import pages_harness as testing
from integration.pages import conftest as page_fixtures

# The page fixtures of tests/integration/pages/conftest.py (this folder is not under it): module globals, so pytest
# finds them here.
pages_app = page_fixtures.pages_app
page_admin = page_fixtures.page_admin
page = page_fixtures.page

TZ = "America/New_York"  # the test app's ui_timezone (the default)
DOC_UA = "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0"


def _span(answer_range: dict[str, Any]) -> int:
    """`to - from` of a range in an answer (the Overview KPI compare range says `start` and `end`)."""
    start: Any = answer_range.get("from", answer_range.get("start"))
    end: Any = answer_range.get("to", answer_range.get("end"))
    return int(end) - int(start)


def _tile(answer: dict[str, Any], key: str) -> dict[str, Any]:
    found: dict[str, Any] | None = next((tile for tile in answer["tiles"] if tile["key"] == key), None)
    assert found is not None, (key, [tile["key"] for tile in answer["tiles"]])
    return found


def _ms(year: int, month: int, day: int, hour: int) -> int:
    return int(datetime(year, month, day, hour, tzinfo=ZoneInfo(TZ)).timestamp() * 1000)


async def _relogin(app: Any, admin: Any) -> None:
    """Sign in again after the fake clock moved past the session's idle timeout."""
    response = await app.harness.login(admin)
    assert response.status_code == 200, response.text


# ================================================================================================ truth-1


async def test_truth_1_month_and_year_comparisons_cover_a_window_as_long_as_the_range(
    page: Any, pages_app: Any
) -> None:
    # A week ending on the 30th, compared with the same week last month and last year (plan 14.2). September 23 to
    # 30 exists in August and in the previous September, and no daylight saving change falls inside either window,
    # so the comparison window must be exactly as long as the range.
    params = {"range": "custom", "from": "2025-09-23T12:00:00", "to": "2025-09-30T12:00:00"}
    # The same home page traffic in both weeks: a visit on the 24th and one on the 29th of each month.
    for month in (8, 9):
        for day in (24, 29):
            pages_app.ctx.recorder.record_visit("home", DOC_UA, at_ms=_ms(2025, month, day, 12))
    await pages_app.flush()
    problems: list[tuple[Any, ...]] = []
    for mode in ("month", "year"):
        kpis = (await page.api("GET", "overview/kpis", params={**params, "compare": mode})).json()
        if _span(kpis["compare"]["range"]) != _span(kpis["range"]):
            problems.append((mode, "kpis", kpis["range"], kpis["compare"]["range"]))
        visitors = (await page.api("GET", "overview/visitors", params={**params, "compare": mode})).json()
        if _span(visitors["compare"]["range"]) != _span(visitors["range"]):
            problems.append((mode, "visitors", visitors["range"], visitors["compare"]["range"]))
    # Same traffic in both weeks: no change. Today the month comparison ends on August 28 and drops the 29th.
    visitors = (await page.api("GET", "overview/visitors", params={**params, "compare": "month"})).json()
    home = _tile(visitors, "home_visits")
    assert home["value"] == 2, home
    if home["delta_pct"] != 0:
        problems.append(("month", "home_visits delta_pct", home["delta"], home["delta_pct"]))
    doc = await page.doc("/admin/overview/fragment/visitors", params={**params, "compare": "month"})
    shown = doc.select_one('[data-kpi="home_visits"] .delta__text')
    if shown is None or shown.text().strip() != "0.0%":
        problems.append(("month", "home_visits on the page", shown.text() if shown else None))
    assert problems == []


# ================================================================================================ truth-2


async def test_truth_2_an_improvement_over_a_negative_avoided_baseline_reads_as_an_improvement(
    page: Any, pages_app: Any, page_admin: Any
) -> None:
    # The previous hour: one request whose Roblox 503 was retried once (1 caller request, 2 upstream calls), so
    # avoided = 1 - 2 = -1 and the avoided share is -100% (plan P6 shows it as it is).
    await pages_app.seed_traffic([testing.PlannedRequest("/catalog.roblox.com/v1/fail/items", "192.0.2.31")])
    pages_app.clock.advance(3720)
    await _relogin(pages_app, page_admin)
    # This hour: six requests for one URL, one miss and five cache hits (6 requests, 1 upstream call): avoided = 5.
    await pages_app.seed_traffic(
        [testing.PlannedRequest("/games.roblox.com/v1/games?universeIds=77", f"203.0.113.{60 + i}") for i in range(6)]
    )
    answer = (await page.api("GET", "overview/kpis", params={"range": "1h", "compare": "previous"})).json()
    avoided, share = _tile(answer, "avoided"), _tile(answer, "avoided_pct")
    assert avoided["value"] == 5, avoided  # demand 6 minus 1 upstream call
    assert avoided["delta"] == 6, avoided  # from -1 to 5: Roxy avoided more calls, the direction "up" is good
    assert share["delta"] is not None, share
    assert share["delta"] > 0, share  # from -100% to 83.33%
    problems: list[tuple[Any, ...]] = []
    for tile in (avoided, share):
        if tile["delta_pct"] is not None and tile["delta_pct"] < 0:
            problems.append(("api", tile["key"], tile["delta"], tile["delta_pct"]))
    doc = await page.doc("/admin/overview/fragment/kpis", params={"range": "1h", "compare": "previous"})
    for key in ("avoided", "avoided_pct"):
        badge = doc.select_one(f'[data-kpi="{key}"] .delta')
        if badge is not None and ("getting worse" in badge.text() or "delta--bad" in (badge.get("class") or "")):
            problems.append(("page", key, " ".join(badge.text().split())))
    cache = (await page.api("GET", "cache/stats", params={"range": "1h", "compare": "previous"})).json()
    cache_avoided = _tile(cache, "avoided")
    if cache_avoided["delta_pct"] is not None and cache_avoided["delta_pct"] < 0:
        problems.append(("cache api", "avoided", cache_avoided["delta"], cache_avoided["delta_pct"]))
    assert problems == []


# ================================================================================================ truth-3


async def _ranged_reset(page: Any, family: str, start: int, end: int) -> dict[str, Any]:
    """A plan 6.8 date range reset of one family through the data API (previewed, then run)."""
    scope = {"scope": "date_range", "families": [family], "from": str(start), "to": str(end)}
    preview = await page.api("POST", "data/resets/preview", json=scope)
    assert preview.status_code == 200, preview.text
    found = preview.json()
    body = {**scope, "preview": found["preview"], "reason": "truth lens reproduction"}
    if found.get("confirm_phrase"):
        body["confirm"] = found["confirm_phrase"]
    done = await page.api("POST", "data/resets", json=body)
    assert done.status_code in (200, 202), done.text
    result: dict[str, Any] = done.json()
    return result


async def test_truth_3_visitor_deltas_over_a_reset_comparison_window_show_the_notice(page: Any, pages_app: Any) -> None:
    now = int(pages_app.clock.now())
    # Four home page visits in the hour before the last hour, two in the last hour: the true change is -50%.
    for at in (now - 5000, now - 5000, now - 4300, now - 4300, now - 600, now - 600):
        pages_app.ctx.recorder.record_visit("home", DOC_UA, at_ms=at * 1000)
    await pages_app.flush()
    params = {"range": "1h", "compare": "previous"}
    before = _tile((await page.api("GET", "overview/visitors", params=params)).json(), "home_visits")
    assert (before["value"], before["delta_pct"]) == (2, -50.0), before
    # The admin resets the visits of a few minutes of the comparison hour (plan 6.8 "Date range").
    result = await _ranged_reset(page, "visits", now - 5100, now - 4800)
    assert result["result"]["deleted"]["metrics.events"] >= 1, result
    after = _tile((await page.api("GET", "overview/visitors", params=params)).json(), "home_visits")
    assert after["value"] == 2, after
    # Plan 6.8: the comparison now covers partial data, so the tile shows a notice instead of a delta (today it says
    # "0.0%": two visits against the two the reset left, as if nothing had changed).
    assert after["delta_pct"] is None, after
    assert after.get("notice"), after
    doc = await page.doc("/admin/overview/fragment/visitors", params=params)
    tile = doc.select_one('[data-kpi="home_visits"]')
    assert tile.select_one(".delta") is None, tile.text()
    assert tile.select_one(".kpi__notice") is not None, tile.text()


async def test_truth_3_the_endpoints_trend_over_a_reset_comparison_window_is_not_new(
    page: Any, pages_app: Any, page_admin: Any
) -> None:
    template_path = "/games.roblox.com/v1/games?universeIds=88"
    await pages_app.seed_traffic([testing.PlannedRequest(template_path, "203.0.113.70")])
    seeded_at = int(pages_app.clock.now())
    pages_app.clock.advance(3720)
    await _relogin(pages_app, page_admin)
    await pages_app.seed_traffic([testing.PlannedRequest(template_path, "203.0.113.71")])
    # The traffic of the comparison hour is reset (plan 6.8 "Date range", family traffic).
    await _ranged_reset(page, "traffic", seeded_at - 120, seeded_at + 120)
    params = {"range": "1h", "compare": "previous"}
    answer = (await page.api("GET", "endpoints", params=params)).json()
    row = next(item for item in answer["items"] if item["key"] == "games.roblox.com/v1/games")
    assert row["requests"] == 1, row
    doc = await page.doc("/admin/endpoints/fragment/table", params=params)
    text = " ".join(doc.text().split())
    problems: list[tuple[Any, ...]] = []
    # The endpoint is not new: its comparison hour was reset. Plan 6.8: say so instead of a trend.
    if "new in this range" in text or "partial data" not in text.lower():
        problems.append(("endpoints table", text[text.find("1/games") : text.find("1/games") + 120]))
    # The comparison overlays of the charts read the reset hour too: their notices must say the comparison is partial
    # (today they list only resets inside the current window).
    for path in ("traffic/requests", "overview/chart"):
        notices = (await page.api("GET", path, params=params)).json()["notices"]
        if not any("partial" in str(notice).lower() for notice in notices):
            problems.append((path, notices))
    assert problems == []


# ================================================================================================ truth-4


# Fixed (fixer g1): the column says "Requests in the last 1, 5, 60 min" (v1's words) over the counts it shows.
async def test_truth_4_top_places_per_minute_column_shows_rates_per_minute(page: Any, pages_app: Any) -> None:
    # One experience sends 2 requests a minute for 5 minutes (10 requests, each from its own server address).
    for minute in range(5):
        await pages_app.seed_traffic(
            [
                testing.PlannedRequest(
                    f"/users.roblox.com/v1/users/{500 + minute * 2 + i}",
                    f"198.51.100.{120 + minute * 2 + i}",
                    place="4242",
                )
                for i in range(2)
            ]
        )
        if minute < 4:
            pages_app.clock.advance(60)
    api = (await page.api("GET", "clients/places", params={"range": "1h"})).json()
    row = next(item for item in api["items"] if item["key"] == "4242")
    assert row["requests"] == 10, row
    # The API's Rate5 and Rate60 are requests in the trailing 5 and 60 minutes (its column help says so).
    assert row["rate60"] == pytest.approx(10.0), row
    doc = await page.doc("/admin/overview/fragment/top-places", params={"range": "1h"})
    header = [" ".join(th.text().split()) for th in doc.select(".ov-top thead th")]
    line = next(tr for tr in doc.select(".ov-top tbody tr") if "4242" in tr.text())
    cells = [" ".join(td.text().split()) for td in line.select("td")]
    # The rates column, whatever its words (skeptic edit: v1's own wording "Requests in the last 1, 5, 60 min" has no
    # "minute", so the column is found by its "60").
    column = next(i for i, text in enumerate(header) if "60" in text or "minute" in text.lower())
    shown = [float(part.replace(",", "")) for part in cells[column - 1].split("/")]
    if "per minute" in header[column].lower():
        # A per minute rate over the last hour is 10 / 60 requests a minute, not 10.
        assert shown[2] == pytest.approx(row["rate60"] / 60, abs=0.01), (header[column], cells[column - 1], row)
        assert shown[1] == pytest.approx(row["rate5"] / 5, abs=0.01), (header[column], cells[column - 1], row)
    else:
        assert shown == pytest.approx([row["rate1"], row["rate5"], row["rate60"]], abs=0.01)


# ================================================================================================ truth-5


# Fixed (shared fixer): one divisor, `storage/read_sizes.py BUDGET_UNIT_BYTES` (1,073,741,824 bytes, as the setting's
# notes say); a regression test now.
async def test_truth_5_the_data_page_and_the_health_check_read_the_disk_budget_in_one_unit(
    page: Any, pages_app: Any
) -> None:
    from roxy.health.runner import runner_for

    await pages_app.settings(storage_total_budget_gb=1)

    def pad(conn: Any) -> None:  # 50 MB of real data, so both shares are well above their rounding
        conn.execute("CREATE TABLE truth_pad (b BLOB)")
        conn.execute("INSERT INTO truth_pad VALUES (zeroblob(50000000))")

    await pages_app.ctx.dbs.metrics.write(pad)
    started = await page.api("POST", "health/runs", json={"checks": ["H-DB-SIZE"], "include_credential": False})
    assert started.status_code == 202, started.text
    run_id = started.json()["run_id"]
    await runner_for(pages_app.ctx).wait(run_id)
    result = (await page.api("GET", f"health/runs/{run_id}")).json()["results"][0]
    assert result["check_id"] == "H-DB-SIZE", result
    assert result["measured"] > 5, result
    # The budget the Health check divided by: its bytes over its percent.
    health_budget = sum(result["detail"]["bytes"].values()) * 100.0 / result["measured"]
    data = (await page.api("GET", "data/storage")).json()
    # The Data page's "Storage budget used" tile divides by `budget_bytes`. One setting, one unit: the two pages
    # must divide by the same number of bytes (today 1,073,741,824 against 1,000,000,000: 7.4 percent apart).
    assert data["budget_bytes"] == pytest.approx(health_budget, rel=0.005), (data["budget_bytes"], health_budget)
    from roxy.notify import producers

    report = await producers.check_storage(pages_app.ctx, pages_app.clock.now())
    assert report["budget_bytes"] == pytest.approx(health_budget, rel=0.005), (report, health_budget)


# ================================================================================================ truth-6
# Fixed (fix_g2): Traffic > Requests charts the outcome measures plus an "Answered by Roxy (OPTIONS)" line
# (`roxy/admin/api/traffic.py outcome_lines`); a regression test now.


async def test_truth_6_traffic_served_by_roblox_leaves_out_options_answered_locally(page: Any, pages_app: Any) -> None:
    statuses = await pages_app.seed_traffic(
        [
            testing.PlannedRequest("/games.roblox.com/v1/games?universeIds=91", "203.0.113.80"),
            testing.PlannedRequest("/games.roblox.com/v1/games?universeIds=91", "203.0.113.81", method="OPTIONS"),
            testing.PlannedRequest("/games.roblox.com/v1/games?universeIds=92", "203.0.113.82", method="OPTIONS"),
        ]
    )
    assert statuses == [200, 204, 204], statuses  # one call to Roblox, two preflights Roxy answered itself
    overview = (await page.api("GET", "overview", params={"range": "1h"})).json()
    served = next(item for item in overview["outcomes"]["items"] if item["outcome"] == "served_upstream")
    assert served["answered_locally"] == 2, served  # the Overview says so ("they never reached Roblox")
    doc = await page.doc("/admin/traffic/fragment/requests", params={"range": "1h"})
    number = doc.select_one(".traffic-stats__item--served_upstream .traffic-stats__number")
    help_text = doc.select_one(".traffic-stats__item--served_upstream .help-dot").get("data-help")
    assert "OPTIONS" in help_text, help_text
    assert "not counted" in help_text, help_text
    assert number.text().strip() == "1", (number.text(), help_text)


# ================================================================================================ truth-7


# Fixed (fixer g7): `GET /system/persistence` labels its writer counts (`writers_scope: this_worker`) and the card
# says "this worker" beside them. A regression test now.
async def test_truth_7_persistence_writer_counts_are_labeled_as_this_workers(page: Any, pages_app: Any) -> None:
    import json

    await pages_app.seed_traffic()
    answer = (await page.api("GET", "system/persistence")).json()
    assert answer["databases"], answer
    assert "writes" in answer["databases"][0], answer
    # `writes` and `write_errors` are this process's DbStats (DESIGN.md 13.1: a value one worker holds is labeled).
    assert "this_worker" in json.dumps(answer), sorted(answer)
    doc = await page.doc("/admin/system/fragment/persistence")
    text = " ".join(doc.text().split()).lower()
    assert "this worker" in text, text[:600]


# ================================================================================================ truth-8


# Fixed (shared fixer): the Roblox 429s tile's share is over every upstream call, callers' and Roxy's own.
async def test_truth_8_internal_429s_are_not_counted_against_caller_traffic(page: Any, pages_app: Any) -> None:
    import httpx

    from roxy.health.runner import runner_for

    # Callers: one request, one upstream call, no 429.
    await pages_app.seed_traffic([testing.PlannedRequest("/users.roblox.com/v1/users/901", "198.51.100.150")])
    # Roxy's own Check Proxy Health meets three Roblox 429s (one reachability probe per host).
    route = next(iter(pages_app.roblox.routes))
    original = route.side_effect
    route.side_effect = lambda request: httpx.Response(429, headers={"Retry-After": "5"}, content=b"{}")
    try:
        hosts = ("games.roblox.com", "users.roblox.com", "catalog.roblox.com")
        started = await page.api(
            "POST", "health/runs", json={"checks": [f"H-REACH-{h}" for h in hosts], "include_credential": False}
        )
        assert started.status_code == 202, started.text
        await runner_for(pages_app.ctx).wait(started.json()["run_id"])
    finally:
        route.side_effect = original
    await pages_app.flush()
    calls = (await page.api("GET", "upstream/internal-calls", params={"range": "1h"})).json()
    assert {item["purpose"]: item["count"] for item in calls["items"]}["health_check"] == 3, calls
    kpis = (await page.api("GET", "overview/kpis", params={"range": "1h"})).json()
    assert _tile(kpis, "upstream_calls")["value"] == 1
    # Plan P6: Roxy's own probes and health checks are reported apart from caller traffic. The tile's share must
    # divide like by like: either the 429s callers met over the calls made for callers (0% here), or every 429 over
    # every upstream call (3 of 4) worded as such. Today it is every 429 over the caller calls: "300.0% of the
    # upstream calls made for callers", a share above 100%.
    # (Skeptic edit: the raw count and `roblox_429_per_10k` are left alone. metrics/catalog.py defines `roblox_429`
    # as every 429 Roblox sent and the per 10,000 figure as "Roblox 429s divided by caller demand", so counting a
    # probe's 429 there is the documented definition, and it never flatters.)
    notice = _tile(kpis, "roblox_429").get("notice") or ""
    shares = [float(found.replace(",", "")) for found in re.findall(r"(\d[\d,]*(?:\.\d+)?)\s*%", notice)]
    assert all(share <= 100.0 for share in shares), notice
    if "for callers" in notice:
        assert shares == [0.0], notice


# ================================================================================================ truth-10


# Fixed (fixer g1): the note words the net count as calls ("22 upstream calls for 26 caller requests, 4 fewer ...").
async def test_truth_10_the_avoided_share_note_counts_requests_that_needed_no_call(page: Any, pages_app: Any) -> None:
    await pages_app.seed_traffic()  # 26 caller requests (refusals left out), 5 cache hits, 22 upstream calls
    kpis = (await page.api("GET", "overview/kpis", params={"range": "1h"})).json()
    served_cache = _tile(kpis, "served_cache")["value"]
    calls, avoided = _tile(kpis, "upstream_calls")["value"], _tile(kpis, "avoided")["value"]
    assert (served_cache, calls, avoided) == (5, 22, 4)  # the Roblox 503 was retried once: 21 + 1 calls
    note = _tile(kpis, "avoided_pct").get("notice") or ""
    # Five requests were answered without any call to Roblox; the 4 is demand minus calls (a retry cost one call).
    if "needed no call" in note:
        claimed = int(note.split(" of ", 1)[0].replace(",", ""))
        assert claimed == served_cache, note
    doc = await page.doc("/admin/overview/fragment/kpis", params={"range": "1h"})
    shown = " ".join(doc.select_one('[data-kpi="avoided_pct"]').text().split())
    assert "4 of 26 caller requests needed no call" not in shown, shown


# ================================================================================================ truth-11


async def test_truth_11_a_day_chart_compares_whole_local_days_across_a_daylight_saving_change(
    page: Any, pages_app: Any
) -> None:
    # 90 days at day granularity (the 90d picker range's granularity) holding the March 9, 2025 change in New York:
    # the window is 90 days minus one hour long. Its previous period must still be 90 whole local days.
    params = {"range": "custom", "from": "2025-02-01T00:00:00", "to": "2025-05-02T00:00:00", "compare": "previous"}
    answer = (await page.api("GET", "overview/chart", params=params)).json()
    assert answer["range"]["granularity"] == "day", answer["range"]
    compare = answer["compare"]["range"]
    start = datetime.fromtimestamp(compare["from"], ZoneInfo(TZ))
    current = next(s for s in answer["series"] if s["key"] == "requests")
    previous = next(s for s in answer["compare"]["series"] if s["key"] == "requests")
    # charts.js overlays the comparison bucket by bucket (point j on point j): same number of whole days, each
    # starting at local midnight, or every compared day lands on the wrong day.
    assert (start.hour, start.minute) == (0, 0), start.isoformat()
    assert len(previous["points"]) == len(current["points"]), (len(previous["points"]), len(current["points"]))
