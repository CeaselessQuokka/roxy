"""P11 adversarial review, lens "v1 parity": reproductions of the findings.

What this is
    One test per confirmed finding of `.remake/p11_review/find_v1parity.md`. Each compares a v2 dashboard page with
    what v1 showed for the same section of the plan 14.1 map (`app/templates/dashboard.html`,
    `app/static/dashboard.js`, `.remake/v1notes/dashboard.md`): the meaning of a number, its window, a column, an
    action or a text. Each was marked `xfail(strict=True)` with the finding id until the P11 review round fixed it;
    the fixed ones are regression tests now. v1parity-1 was deferred to the lead and fixed in the final review (its
    comment says how); the refuted v1parity-7 (v1's default sort orders, which no plan section requires) has no test.

Why it exists
    The acceptance test `tests/e2e/test_v1_sections.py` proves that every v1 section has a home (the selectors are
    there); these tests check that what is at home means what v1 meant (plan C3, parity rows 1 to 135).

How it works
    The fixtures of `tests/integration/pages/conftest.py` (the real app in process, a signed-in admin, traffic sent
    through the real proxy). Numbers are read from the rendered page or fragment, never from a second query.

What to read next
    `.remake/p11_review/find_v1parity.md`, `roxy/admin/pages/registry.py V1_SECTIONS`, `.remake/v1notes/dashboard.md`.
"""

# The page fixtures are imported from tests/integration/pages/conftest.py (this folder has no conftest of its own),
# so every test's `page` and `pages_app` parameters shadow the imported names on purpose.
# ruff: noqa: F811

from __future__ import annotations

from typing import Any

import pytest

from integration.pages.conftest import anon, page, page_admin, pages_app  # noqa: F401
from pages_harness import Node, PlannedRequest, parse_html


def _kpi_number(doc: Node, key: str) -> str:
    """The value text of one KPI tile (`components/kpi.html`: `[data-kpi=<key>] .kpi__number`)."""
    node = doc.select_one(f'[data-kpi="{key}"] .kpi__number')
    assert node is not None, key
    return node.text().strip()


# ============================================================================================ v1parity-1


# Fixed in the final review (fixer data, lead decision 11, with data-3): the tiles `status_2xx`, `status_4xx` and
# `roblox_5xx` count Roblox's answers per attempt from the `roblox_answer_*` tables (metrics 0010); the caller's final
# statuses are `caller_2xx`, `caller_4xx`, `status_5xx` and `caller_roblox_5xx`.
async def test_v1parity_1_the_status_tiles_count_roblox_answers_like_v1(
    page: Any, pages_app: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """v1 `log_status_code` (app/diagnostics.py, called for every upstream answer in proxy.py): "Only Roblox counts
    toward the 2xx/4xx headline totals ... folding our own refusals in would let a burst of our own throttling read
    as Roblox starting to reject us". v1's "5xx from Roblox" tile: "Times Roblox's own servers failed on us ... if
    the cache is set to serve expired answers, your callers may not have noticed" (dashboard.md 9.1, L2628)."""
    import pages_harness

    real_answer = pages_harness.roblox_answer
    flaky_calls: list[int] = []

    def answer(host: str, path: str) -> tuple[int, dict[str, str], bytes]:
        if "/flaky" in path:  # Roblox fails the first call with a 503 and answers the retry
            flaky_calls.append(1)
            if len(flaky_calls) == 1:
                return 503, {"Content-Type": "application/json"}, b'{"errors":[]}'
        return real_answer(host, path)

    monkeypatch.setattr(pages_harness, "roblox_answer", answer)
    looper = "198.51.100.77"
    plan = [
        PlannedRequest(f"/games.roblox.com/v1/games?universeIds={500 + i}", looper, user_agent="LoopBot/0.1")
        for i in range(14)
    ]
    # Three repeats from another address: answered from the cache, so Roblox never answered them.
    plan += [PlannedRequest("/games.roblox.com/v1/games?universeIds=500", "198.51.100.78") for _ in range(3)]
    # One call Roblox fails with a 503, which Roxy's retry turns into a 200 for the caller.
    plan.append(PlannedRequest("/badges.roblox.com/v1/flaky/1", "203.0.113.181"))
    statuses = await pages_app.seed_traffic(plan)
    roxy_refusals = statuses[:14].count(429)
    roblox_answers_2xx = statuses[:14].count(200) + 1  # the retried call's 200
    assert roxy_refusals >= 1, statuses  # the per-IP limit refused some of them (Roxy's own 429s)
    assert statuses[14:] == [200, 200, 200, 200], statuses
    assert len(flaky_calls) == 2, flaky_calls  # Roblox answered the flaky call twice: 503, then 200
    doc = parse_html((await page.fragment("overview", "kpis", range="1h")).text)
    # v1: 4xx Client Errors = "Times Roblox refused one of our requests"; Roblox refused none here.
    assert _kpi_number(doc, "status_4xx") == "0"
    # v1: 2xx Success = "Times Roblox answered us successfully"; the three cache serves are not Roblox's answers.
    assert _kpi_number(doc, "status_2xx") == str(roblox_answers_2xx)
    # v1: 5xx from Roblox counts the 503 even though the caller never saw it.
    assert _kpi_number(doc, "roblox_5xx") == "1"
    traffic = parse_html((await page.fragment("traffic", "status", range="1h")).text)
    assert _kpi_number(traffic, "roblox_5xx") == "1"


# ============================================================================================ v1parity-2


# Fixed (fixer g1): the Overview reads the uptime from the master as System > Fleet does (read_fleet.service_since).
async def test_v1parity_2_the_overview_service_uptime_is_the_masters_like_v1_and_the_system_page(
    page: Any, pages_app: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """v1 `workers.py`: ServiceStartedAt is pinned to the gunicorn master; plan parity row 84: "service uptime per
    color (since that master started; survives worker recycles because it is read from the master pid)". Here the
    master has run for a day and this worker was started (recycled) a moment ago."""
    from roxy.scheduler import read_fleet

    now = int(pages_app.clock.now())
    master_started = now - 86_400
    monkeypatch.setattr(read_fleet, "process_started_at", lambda pid, **_: master_started)

    def recycled(conn: Any) -> None:
        # This worker's heartbeat as a worker recycled a minute ago would write it (gunicorn max_requests).
        conn.execute("UPDATE worker_heartbeat SET started_at = ?, last_seen = ?", (now - 60, now))

    await pages_app.ctx.dbs.metrics.write(recycled)
    fleet = (await page.api("GET", "system/fleet")).json()
    mine = next(color for color in fleet["colors"] if color["is_this_color"])
    assert mine["service_uptime_s"] is not None, mine
    assert mine["service_uptime_s"] >= 86_400, mine
    system = parse_html((await page.fragment("system", "fleet")).text)
    overview = parse_html((await page.fragment("overview", "kpis")).text)
    # One v1 tile (plan 14.1 row 3: Overview > KPI tiles; System > Fleet), one number.
    assert _kpi_number(overview, "service_uptime_s") == _kpi_number(system, "service_uptime_s")


# ============================================================================================ v1parity-3


# Fixed in the P11 review round (v1parity-3, shared fixer): a regression test now.
async def test_v1parity_3_the_live_tail_filters_by_refusal_kind_like_v1(page: Any) -> None:
    """v1 `#liveOutcomeFilter` listed every refusal kind (dashboard.md 4.5); parity row 81 asks for the outcome
    filter to be complete. The Live API and the stream already take `reason` (`live_api.live_query`)."""
    doc = await page.doc("/admin/live", params={"reason": "header_rule"})
    handed = doc.select_one("[data-live-filters]")
    assert handed is not None
    assert '"reason": "header_rule"' in (handed.get("data-live-filters") or "")
    control = doc.select_one('[data-live-tail] select[data-tail-filter="reason"]')
    assert control is not None
    values = {option.get("value") for option in control.select("option")}
    # v1's outcome options that v2 lumps into "Refused by Roxy" (plus the two v1 forgot, bug 16).
    for code in ("throttle", "throttle_all", "endpoint_blocked", "endpoint_rule", "header_rule", "user_agent_rule"):
        assert code in values, code


# ============================================================================================ v1parity-4


# Fixed in the P11 review round (v1parity-4, shared fixer): a regression test now.
async def test_v1parity_4_persistence_is_ok_again_once_writes_succeed_like_v1(page: Any, pages_app: Any) -> None:
    """v1 `renderPersistence` (dashboard.md 4.25): PROBLEM when not writable, or LastErrorAt > LastWriteOK, or the
    stats file was set aside. One failed write followed by good writes is OK again."""
    import sqlite3

    def broken(conn: Any) -> None:
        conn.execute("INSERT INTO no_such_table VALUES (1)")

    with pytest.raises(sqlite3.Error):
        await pages_app.ctx.dbs.control.write(broken)
    for value in (151, 152, 153):  # good writes after it, through the real settings service
        await pages_app.settings(cache_ttl_seconds=value)
    response = await page.fragment("system", "persistence")
    assert response.status_code == 200, response.status_code
    doc = parse_html(response.text)
    status = doc.select_one(".system-status")
    assert status is not None
    assert "Problem" not in status.text(), status.text()


# ============================================================================================ v1parity-5


# Fixed (fixer g5; its metrics recorder and read model part, .remake/p11_review/fix_g5_requests.patch, applied by
# the shared fixer): a regression test now.
async def test_v1parity_5_header_blocked_attempts_say_which_header_and_text_matched_like_v1(
    page: Any, pages_app: Any
) -> None:
    """v1 `#headerBlockedTable` (dashboard.md 4.13): Rule / Blocked / Unique IPs / Last Header / Triggered By (Header
    name or Header value) / Matched Text / Last IP / Last Path / Last Attempt. A filter on any header's name catches
    a header the admin never named: only the attempts log says which one it was."""
    created = await page.api(
        "POST", "protection/header-rules", json={"needle": "xeno", "scope": "either", "mode": "contains"}
    )
    assert created.status_code in (200, 201), created.text
    client = pages_app.harness.new_client()
    response = await client.get(
        "/games.roblox.com/v1/games?universeIds=700",
        headers={"User-Agent": "Roblox/WinInet", "X-Forwarded-For": "203.0.113.170", "X-Xeno-Fingerprint": "4f3a91c0"},
    )
    assert response.status_code == 429, response.status_code  # the stealth refusal of a request filter
    await pages_app.flush()
    doc = parse_html((await page.fragment("protection", "request-filters", table="attempts", range="1h")).text)
    rows = doc.select("tbody tr[data-row-id]")
    assert len(rows) == 1, [row.text() for row in rows]
    text = rows[0].text()
    assert "X-Xeno-Fingerprint" in text, text  # v1 Last Header
    assert "Header name" in text, text  # v1 Triggered By: the rule matched the header's name, not a value


# ============================================================================================ v1parity-6


# Fixed (fixer g5): the watch lists the clients refused since the marker, refused most first (throttle_all.turned_away).
async def test_v1parity_6_the_emergency_limit_watch_lists_who_it_turned_away_like_v1(page: Any, pages_app: Any) -> None:
    """v1 `renderThrottleWatch` (dashboard.md 4.1): rows are the IPs with Refused > 0, worst first, so the brake
    can be judged and released. Here an abuser is refused, goes quiet for a period, and a polite client calls once."""
    abuser, polite = "203.0.113.171", "203.0.113.172"
    body = {"enabled": True, "message": "Slow down for the check.", "limit": 1, "period": 60, "reason": "v1 parity"}
    try:
        switched = await page.api("POST", "protection/throttle-all", json=body)
        assert switched.status_code == 200, switched.text
        statuses = await pages_app.seed_traffic(
            [PlannedRequest(f"/games.roblox.com/v1/games?universeIds={710 + i}", abuser) for i in range(4)]
        )
        assert statuses.count(429) == 3, statuses
        pages_app.clock.advance(61)  # the abuser's emergency window ends; the brake is still on
        assert await pages_app.seed_traffic([PlannedRequest("/games.roblox.com/v1/games?universeIds=720", polite)]) == [
            200
        ]
        doc = parse_html((await page.fragment("protection", "throttle-all", table="watch-all")).text)
        table = doc.select_one("#prot-watch-all")
        assert table is not None
        assert table.select_one(f"tr[data-row-id=watch-all-{abuser}]") is not None  # turned away 3 times
        assert table.select_one(f"tr[data-row-id=watch-all-{polite}]") is None  # never refused
    finally:
        await page.api("POST", "protection/throttle-all", json={"enabled": False})


# ============================================================================================ v1parity-8


# Fixed in the P11 review round (v1parity-8, shared fixer): a regression test now.
async def test_v1parity_8_the_upstream_internal_calls_and_errors_cards_have_their_inline_reset(
    page: Any, pages_app: Any
) -> None:
    """Plan 6.8, "Inline on page / card": a metric family's reset sits on the card that shows the family (Upstream >
    Calls for `upstream`, Upstream > Internal calls for `internal_calls`, System > Errors for `errors`), as v1's
    `Clear data` sat on Request Failures, Internal Requests and Error Log (dashboard.md 4.19). A link to Data > Resets
    with the family preselected (the Security cards' `reset_action`) or the shared drawer of `resets.py` both count.

    Skeptic narrowing: the finding also asked that v1's `request_failures` target keep the Roblox 429 log. Plan 6.8's
    families have no narrower one than `upstream`, CHANGES.md records the mapping and the family's tables, and the
    preview lists every table before anything is deleted, so that part is not pinned here."""
    await pages_app.seed_traffic()  # the harness plan has a Roblox 429 (/too-many) and a Roblox 503 (/fail)
    reset = '[data-action*="clear"], [data-action*="reset"]'
    # Family `upstream` (failure events, the 429 log, attempts): v2 has no "Calls" card; its registry card is
    # upstream#health, and the Request failures card is where v1's clear sat. Either one counts.
    upstream = [parse_html((await page.fragment("upstream", card, range="1h")).text) for card in ("health", "failures")]
    assert any(doc.select(reset) for doc in upstream), "Upstream > Calls (family upstream)"
    internal = parse_html((await page.fragment("upstream", "internal-calls", range="1h")).text)
    assert internal.select(reset), "Upstream > Internal calls (family internal_calls)"
    errors = parse_html((await page.fragment("system", "errors")).text)
    assert errors.select(reset), "System > Errors (family errors)"


# ============================================================================================ v1parity-9


# Fixed in the P11 review round (v1parity-9, shared fixer): a regression test now.
async def test_v1parity_9_the_bypass_texts_name_every_check_a_bypass_skips(page: Any, pages_app: Any) -> None:
    """v1's Throttle Bypass hint listed exactly what a bypass skips and what it does not (dashboard.md 4.10); v2's
    bypass also skips the flood, spam, challenge and bot score checks (CHANGES.md "Bypass scope",
    `abuse/checks/*.py skipped_by_bypass`). The admin deciding to bypass an address is told only half of it."""
    from roxy.abuse.checks import default_checks

    # The checks' own flags are the truth; the words each check is known by on the dashboard must be in the text.
    skipped = {check.name for check in default_checks() if check.skipped_by_bypass}
    words = {"flood": "flood", "spam": "spam", "challenge": "challenge", "bot_score": "bot score"}
    assert set(words) <= skipped, skipped
    card = parse_html((await page.fragment("protection", "bypass")).text)
    text = card.text().lower()
    for name, word in words.items():
        assert word in text, (name, "Protection > Bypass")


# ============================================================================================ v1parity-10


# Fixed (fixer g5): the trend compares the last hour with the period before it, a day at least (protection.py).
async def test_v1parity_10_the_tarpit_trend_compares_the_hour_with_a_longer_baseline_like_v1(
    page: Any, pages_app: Any
) -> None:
    """v1 tile "Time Between Requests" (dashboard.md 4.11): ratio = AvgGap(last hour) / lifetime gap; 1.15 or more
    reads "Backing off". Held callers waited 10 s between requests six hours ago and 30 s in the last hour."""
    now = int(pages_app.clock.now())
    minute = now - now % 60
    old = minute - 6 * 3600

    def seed(conn: Any) -> None:
        sql = (
            "INSERT INTO tarpit_minute (bucket_start, category, kind, holds, skipped, held_s_sum, held_s_max, "
            "gaps_after_hold, gap_after_hold_s_sum, gaps_after_instant, gap_after_instant_s_sum) "
            "VALUES (?, 'probe', 'hold', 10, 0, 100.0, 15.0, 10, ?, 0, 0.0)"
        )
        conn.execute(sql, (old, 100.0))  # a 10 s gap on average
        conn.execute(sql, (minute, 300.0))  # a 30 s gap on average: the tarpit is slowing them down

    await pages_app.ctx.dbs.metrics.write(seed)
    doc = parse_html((await page.fragment("protection", "tarpit", range="1h")).text)
    tile = doc.select_one('[data-kpi="tarpit_gap"]')
    assert tile is not None
    assert "Backing off" in tile.text(), tile.text()
