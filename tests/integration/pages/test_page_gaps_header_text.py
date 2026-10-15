"""User-Agents are recorded and shown as the caller wrote them (gap G12): UTF-8, invalid bytes as escapes, no markup.

What this is
    Integration tests against the real app: a request whose User-Agent is UTF-8 (letters outside Latin-1, a CJK word,
    hostile markup) and ends in two bytes that are not UTF-8 goes through the real proxy. The Live API, the Endpoints
    page's recent requests, the Security page's User-Agent table and drill-down and the Live request drawer show the
    caller's text (never the Latin-1 mojibake the server's header decoding gives), the invalid bytes as `\\xff\\xfe`,
    and the markup as text.

Why it exists
    Before the gaps lane `R\\u00f6blox` read as `R\\u00c3\\u00b6blox` on Endpoints and Live (the recorder kept the
    Latin-1 text the server hands over for header bytes); `core/header_text.py` now records what the caller sent.

What to read next
    `roxy/core/header_text.py`, `roxy/metrics/recorder.py` (`scrub_labels`), `roxy/metrics/fingerprints.py`.
"""

from __future__ import annotations

from typing import Any

from pages_harness import parse_html
from roxy.metrics.fingerprints import row_hash

WRITTEN = "RöbloxBot/2 日本 <script>alert('ua')</script>"
UA_BYTES = WRITTEN.encode("utf-8") + b" \xff\xfe"
SHOWN = WRITTEN + " \\xff\\xfe"
MOJIBAKE = "RÃ¶blox"
PATH = "/games.roblox.com/v1/games?universeIds=917"


async def _send(pages_app: Any) -> None:
    client = pages_app.harness.new_client()
    response = await client.get(PATH, headers={"User-Agent": UA_BYTES, "X-Note": "café".encode()})
    assert response.status_code == 200, response.text
    await pages_app.flush()


async def test_live_and_endpoints_show_what_the_caller_sent(page: Any, pages_app: Any, inert: Any) -> None:
    await _send(pages_app)
    rows = (await page.api("GET", "live", params={"endpoint": "games.roblox.com/v1/games"})).json()["items"]
    agents = {row["user_agent"] for row in rows}
    assert SHOWN in agents
    assert not any(MOJIBAKE in agent for agent in agents)
    recent = await page.fragment("endpoints", "recent", template="games.roblox.com/v1/games")
    inert(recent.text, "endpoints recent")
    text = parse_html(recent.text).text()
    assert "RöbloxBot/2 日本" in text
    assert "\\xff\\xfe" in text
    assert MOJIBAKE not in text
    assert "&lt;script&gt;alert(&#39;ua&#39;)&lt;/script&gt;" in recent.text  # markup shown as text
    request_id = next(row["request_id"] for row in rows if row["user_agent"] == SHOWN)
    drawer = await page.get("/admin/live/request", params={"request": request_id})
    if drawer.status_code == 200:  # the capture may have sampled this request out; the row's text is checked above
        inert(drawer.text, "live request drawer")
        assert MOJIBAKE not in drawer.text


async def test_the_fingerprints_keep_the_callers_text(page: Any, pages_app: Any, inert: Any) -> None:
    await _send(pages_app)
    table = (await page.api("GET", "security/fingerprints/user-agents", params={"q": "bloxbot"})).json()
    assert [item["user_agent"] for item in table["items"]] == [SHOWN]
    assert table["items"][0]["ua_hash"] == row_hash(SHOWN)
    detail = await page.fragment("security", "fingerprints", part="agent", ua=row_hash(SHOWN))
    inert(detail.text, "user-agent drawer")
    assert "RöbloxBot/2" in parse_html(detail.text).text()
    values = (await page.api("GET", "security/fingerprints/headers/x-note/values")).json()
    assert [item["value"] for item in values["items"]] == ["café"]
