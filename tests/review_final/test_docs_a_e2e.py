"""Final review, lens docs_a: reproductions only a browser shows (the dashboard's own scripts).

What this is
    The browser half of `tests/review_final/test_docs_a.py`: findings of `.remake/final_review/find_docs_a.md` whose
    wrong behavior lives in the dashboard's JavaScript (the live tail's filter, the chart's comparison overlay, the
    Live page's address filters). Each was a strict xfail naming its finding until the final review fixed it, and is a
    regression test now. The fixtures are those of
    `tests/e2e/conftest.py` (`dashboard`: the real app on a free loopback port with a signed-in admin and seeded
    traffic; `open_admin`: a page in its own browser context), imported as the e2e tests get them.

Why it exists
    The admin guide had to work around each of these ("the list can stay empty", "only Latency percentiles draws the
    comparison"); a fix must make the guide's workaround unnecessary, and these tests say when it did.

How it works
    Each test sends the requests it needs through the real proxy first (`dashboard.send_traffic`), so the live
    records (kept 15 minutes) and the Roblox 429 log hold what it looks for whatever ran before in the session, then
    waits for the page's own scripts. Every request stays on loopback.

What to read next
    `static/js/live_tail.js`, `static/js/pages/live.js`, `static/js/charts.js`, `roxy/admin/api/upstream.py`.
"""

# ruff: noqa: F811  (the imported pytest fixtures are the tests' parameters)

from __future__ import annotations

import json
import time
from typing import Any
from urllib.parse import urlencode

from e2e.conftest import browser, dashboard, open_admin  # noqa: F401  (the browser fixtures)
from pages_harness import DOC_NETS, PlannedRequest

TAIL = "#live-tail"
SHOWN = f"document.querySelectorAll('{TAIL} .tail__row:not([hidden])').length"


def eventually(page: Any, expression: str, timeout_s: float) -> bool:
    """True once `expression` is truthy in the page, False at the deadline (never raises on a slow page)."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            if page.evaluate(expression):
                return True
        except Exception:  # the page is navigating: try again on the new document
            pass
        page.wait_for_timeout(250)
    return False


# ===================================================================================================== docs_a-6


def test_watch_it_live_shows_the_requests_of_a_template_with_a_placeholder(open_admin: Any, dashboard: Any) -> None:
    """`pages/endpoints.py` "Watch it live" opens `/admin/live?endpoint=<template>`. The server's filter
    (`read_dashboard.LiveQuery.matches`) matches the template OR the url, so the stream sends the rows; but
    `static/js/live_tail.js matches()` tests only `row.endpoint`, which `admin/sse.py live_payload` sets to the
    concrete url. `users.roblox.com/v1/users/{...}` is a substring of no real path, so every row is hidden and the
    list stays empty although the server streamed matching requests. The guide had to tell the owner to shorten the
    text to a fixed part of the path (Endpoints > Recent requests, Live > filters)."""
    plan = [
        PlannedRequest(f"/users.roblox.com/v1/users/{710 + i}", f"{DOC_NETS[1]}.{80 + i}", note="docs_a watch live")
        for i in range(3)
    ]
    dashboard.send_traffic(plan)
    mine = dashboard.api("GET", "live", params={"endpoint": "users.roblox.com/v1/users/71", "limit": 5}).json()
    assert mine["items"], "the requests just sent are in the live records"
    template = str(mine["items"][0]["template"])
    assert "{" in template, template
    assert template.startswith("users.roblox.com/v1/users/"), template
    served = dashboard.api("GET", "live", params={"endpoint": template, "limit": 5}).json()["items"]
    assert served, "the server's own filter finds the requests of this template"

    admin = open_admin("/admin/live?" + urlencode({"endpoint": template}))
    page = admin.page
    admin.wait(f"document.querySelector('{TAIL}').dataset.state === 'live'", timeout=20)
    field = f"document.querySelector('{TAIL} input[data-tail-filter=\"endpoint\"]').value === {json.dumps(template)}"
    admin.wait(field, timeout=20)  # live.js put the address's template in "Endpoint contains"
    dashboard.send_traffic(  # one more after the page listens, so the stream has a fresh matching row too
        [PlannedRequest("/users.roblox.com/v1/users/790", f"{DOC_NETS[1]}.90", note="docs_a watch live")]
    )
    shown = eventually(page, f"{SHOWN} > 0", 20)
    count = page.evaluate(f"document.querySelector('{TAIL} [data-tail-count]').textContent")
    assert shown, f"the Live list stays empty for the template Watch it live put there (tail count: {count})"


# ===================================================================================================== docs_a-9


def test_the_roblox_429_chart_draws_the_comparison_like_the_latency_chart(open_admin: Any, dashboard: Any) -> None:
    """`admin/api/upstream.py timeline_429_answer` sends the main series as `roblox_429:<template>` and
    `roblox_429:other`, and the comparison as one `roblox_429:total` series. `static/js/charts.js specFromSeries`
    overlays a compare series only on a main series with the same key, so the comparison of the page's most
    important chart is dropped without a word, while Latency percentiles on the same page draws its own. The guide
    had to say "the Latency percentiles chart draws the comparison period" and nothing else does."""
    dashboard.send_traffic(  # Roblox answers these 429 (the stand-in's /too-many paths): the chart has data
        [PlannedRequest("/thumbnails.roblox.com/v1/too-many?size=60x60", f"{DOC_NETS[2]}.31", note="docs_a 429")]
    )
    admin = open_admin("/admin/upstream?" + urlencode({"range": "24h", "compare": "previous"}))
    page = admin.page
    admin.settle()
    latency_compare = "document.querySelector('#chart-upstream-latency [data-series=\"compare\"]') !== null"
    assert eventually(page, latency_compare, 20), "the control: Latency percentiles draws the comparison"
    drawn = "document.querySelectorAll('#chart-roblox-429 .legend-item').length > 0"
    assert eventually(page, drawn, 20), "the Roblox 429s chart is drawn"
    shown = page.evaluate("document.querySelector('#chart-roblox-429 [data-series=\"compare\"]') !== null")
    assert shown, "the Roblox 429s chart draws no comparison although one is chosen"


# ===================================================================================================== docs_a-16


def test_a_live_address_filter_is_applied_or_said_to_be_ignored(open_admin: Any, dashboard: Any) -> None:
    """`pages/live.py address_filters` checks the address with the API's parser, which accepts a status code
    (`404`), a lower-case cache state (`hit`) and comma lists, so no "not valid" note is rendered. `static/js/pages/
    live.js applyFilters` then skips any value that is not one of the select's options, so the field keeps "Any
    status" and the stream is not filtered either: the page shows every request under an address that says 404."""
    dashboard.send_traffic(
        [
            PlannedRequest(f"/users.roblox.com/v1/users/{820 + i}", f"{DOC_NETS[1]}.{95 + i}", note="docs_a")
            for i in range(2)
        ]
    )
    admin = open_admin("/admin/live?status=404")
    page = admin.page
    admin.wait(f"document.querySelector('{TAIL}').dataset.state === 'live'", timeout=20)
    page.wait_for_timeout(1500)  # live.js applies the address filters once the tail is ready
    applied = page.evaluate(f"document.querySelector('{TAIL} select[data-tail-filter=\"status\"]').value === '404'")
    noted = "every request is shown" in page.locator("main").inner_text()
    statuses = page.locator(f"{TAIL} .tail__row:not([hidden]) .tail__status").all_inner_texts()
    assert applied or noted, f"status=404 was ignored in silence; the list shows statuses {sorted(set(statuses))[:5]}"
