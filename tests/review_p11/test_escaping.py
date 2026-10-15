"""Review of the P11 dashboard pages, lens "injection and escaping": reproductions of esc-1 to esc-5 (regression tests).

What this is
    One test per finding of `.remake/p11_review/find_escaping.md`. Each one drives the real app in process (the
    fixtures of `tests/integration/pages/conftest.py`: the real proxy, the real admin login, the real read models)
    or, for the insights evidence links, the insights fixture harness (`tests/insights/harness.py`), and asserts
    what the dashboard must do with text a caller chose. Every test was `xfail(strict=True)` until its finding was
    fixed in the P11 review round; each is now a regression test (a comment above it names the fix).

Why it exists
    The page tests prove that hostile text renders as inert markup (no tag, no handler, no `javascript:` link) and
    they hold: no template, fragment or script turns caller text into markup. These findings are the other half of
    the lens: caller text that is read as syntax somewhere else (a glob or template placeholder, a URL dot segment,
    a line separator, a query separator, JSON nesting), so an admin's click does something other than what the page
    says, or a drawer fails.

How it works
    Traffic goes through the real proxy with the hostile text in the path, a header name, a User-Agent, the
    Roblox-Id header or the body; the admin's action is taken exactly as the page's script would take it (the URL
    and the values the rendered HTML carries, a URL resolved the way a browser resolves it before `fetch`), then
    the test checks the effect through the admin API.

What to read next
    `.remake/p11_review/find_escaping.md`, `roxy/admin/pages/cache.py`, `roxy/admin/pages/security.py`,
    `roxy/admin/pages/live.py`, `roxy/admin/pages/texts.py`, `roxy/abuse/header_rules.py`,
    `roxy/insights/rules/abuse.py`.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import yaml

from integration.pages.conftest import page, page_admin, pages_app  # noqa: F401
from pages_harness import Node, parse_html
from roxy.rules.match import matches

ROBLOX_UA = "Roblox/WinInet"


def browser_url(url: str) -> str:
    """`url` (a path on this site) as a browser's URL parser leaves it before `fetch` sends it (WHATWG URL
    standard, path state): a single-dot segment (`.` or `%2e`, any case) is dropped and a double-dot segment (`..`,
    `.%2e`, `%2e.`, `%2e%2e`) also drops the segment before it; a dot segment at the end leaves an empty last
    segment (a trailing slash). The query is kept as it is."""
    path, sep, query = url.partition("?")
    segments = path.split("/")[1:]
    out: list[str] = []
    for index, segment in enumerate(segments):
        last = index == len(segments) - 1
        lowered = segment.lower()
        if lowered in (".", "%2e"):
            if last:
                out.append("")
            continue
        if lowered in ("..", ".%2e", "%2e.", "%2e%2e"):
            if out:
                out.pop()
            if last:
                out.append("")
            continue
        out.append(segment)
    return "/" + "/".join(out) + sep + query


def ancestor_text(node: Node, tag: str) -> str:
    walker: Node | None = node
    while walker is not None and walker.tag != tag:
        walker = walker.parent
    return walker.text() if walker is not None else ""


async def send(
    running: Any,
    path: str,
    ip: str,
    *,
    method: str = "GET",
    user_agent: str = ROBLOX_UA,
    headers: dict[str, Any] | None = None,
    body: bytes | None = None,
) -> Any:
    """One request through the real proxy (in process), from `ip`, with the hostile text where the test puts it."""
    client = running.harness.new_client()
    sent: dict[str, Any] = {
        "X-Forwarded-For": ip,
        "User-Agent": user_agent if user_agent.isascii() else user_agent.encode("utf-8"),
    }
    for name, value in (headers or {}).items():
        sent[name] = value if not isinstance(value, str) or value.isascii() else value.encode("utf-8")
    return await client.request(method, path, headers=sent, content=body)


# ======================================================================================= esc-1 (template syntax)


# Fixed in the P11 review round (esc-1, shared fixer): a regression test now.
async def test_a_star_in_a_caller_path_never_widens_the_purge_or_rule_offered_for_that_endpoint(
    page: Any,  # noqa: F811
    pages_app: Any,  # noqa: F811
) -> None:
    await pages_app.seed_traffic()  # caches games.roblox.com/v1/games?universeIds=... (another endpoint)
    for value in ("1", "2", "3"):  # one junk endpoint whose stored answers split on a parameter (the spread card)
        answer = await send(pages_app, f"/games.roblox.com/*?x={value}", "203.0.113.180")
        assert answer.status_code == 200
    await pages_app.flush()

    async def stored_others() -> int:
        listing = await page.api("GET", "cache/entries", params={"q": "games.roblox.com/v1/games?", "page_size": 250})
        assert listing.status_code == 200, listing.text
        return int(listing.json()["total"])

    before = await stored_others()
    assert before >= 10

    # The endpoint drawer (Cache > Endpoints row): "Write the rule" and "Purge its stored answers" for this endpoint
    # must not cover games.roblox.com/v1/games.
    drawer = parse_html(
        (await page.get("/admin/cache/drawer/endpoint", params={"template": "games.roblox.com/*"}, htmx=True)).text
    )
    rule_pattern = drawer.select_one('form[data-api-form] input[name="pattern"]')
    rule_type = drawer.select_one('form[data-api-form] input[name="type"]')
    assert rule_pattern is not None
    assert rule_type is not None
    purge_fill = json.loads(drawer.select_one('[data-action="cache-endpoint-purge"]').get("data-fill") or "{}")
    covered = {
        "rule": matches(rule_pattern.get("value") or "", "games.roblox.com/v1/games", rule_type.get("value") or "glob"),
        "drawer purge": purge_fill.get("scope") == "pattern"
        and matches(str(purge_fill.get("value")), "games.roblox.com/v1/games", str(purge_fill.get("type") or "glob")),
    }

    # The key spread card's "Purge" on the junk endpoint's row, sent as the purge dialog sends it.
    spread = parse_html((await page.fragment("cache", "spread")).text)
    buttons = [
        button
        for button in spread.select('[data-action="cache-spread-purge"]')
        if "games.roblox.com/*" in ancestor_text(button, "tr")
    ]
    assert len(buttons) == 1, [ancestor_text(b, "tr") for b in spread.select('[data-action="cache-spread-purge"]')]
    fill = json.loads(buttons[0].get("data-fill") or "{}")
    body = {key: value for key, value in fill.items() if not key.startswith("_")}
    body.setdefault("include_stale", False)
    body["reason"] = "review esc-1"
    purged = await page.api("POST", "cache/purge", json=body)
    assert purged.status_code == 200, purged.text
    after = await stored_others()

    problems = [
        f"the endpoint drawer's {name} covers games.roblox.com/v1/games" for name, yes in covered.items() if yes
    ]
    if after != before:
        problems.append(
            f"the spread card's purge of games.roblox.com/* removed {before - after} of {before} other answers"
        )
    assert not problems, " | ".join(problems)


# ======================================================================================= esc-2 (dot segments)


# Fixed in the P11 review round (esc-2, shared fixer): a regression test now.
async def test_a_dot_name_keeps_its_drawer_and_row_actions_on_its_own_record(
    page: Any,  # noqa: F811
    pages_app: Any,  # noqa: F811
) -> None:
    answer = await send(
        pages_app,
        "/games.roblox.com/v1/games?universeIds=181",
        "203.0.113.181",
        headers={".": "dotvalue", "values": "kept"},
    )
    assert answer.status_code == 200
    await pages_app.flush()
    listed = (await page.api("GET", "security/fingerprints/headers", params={"page_size": 250})).json()
    names = {item["name"] for item in listed["items"]}
    assert {".", "values"} <= names  # any caller can send a header named "." (a token character)

    # Security > Fingerprints > header "." > "Clear the values", sent the way the browser sends the form.
    drawer = parse_html((await page.fragment("security", "fingerprints", part="header", name=".")).text)
    forms = [
        form
        for form in drawer.select("form[data-api-form]")
        if "values of this header were cleared" in (form.get("data-success") or "")
    ]
    assert len(forms) == 1
    form = forms[0]
    cleared = await page.api(
        form.get("data-api-method") or "POST", browser_url(form.get("data-api-url") or ""), json={}
    )
    after = (await page.api("GET", "security/fingerprints/headers", params={"page_size": 250})).json()
    left = {item["name"] for item in after["items"]}

    # Cache > Ignored parameters > "." > "Stop ignoring" (the dialog takes the row's `_url`).
    added = await page.api("POST", "cache/ignored-params", json={"name": ".", "reason": "review esc-2", "purge": False})
    assert added.status_code in (200, 201), added.text
    rows = parse_html((await page.fragment("cache", "ignored-params")).text)
    unignore = [
        json.loads(button.get("data-fill") or "{}")
        for button in rows.select('[data-action="cache-unignore"]')
        if json.loads(button.get("data-fill") or "{}").get("_label") == "."
    ]
    assert len(unignore) == 1
    removed = await page.api("DELETE", browser_url(str(unignore[0]["_url"])), json={"reason": "review esc-2"})
    still = (await page.api("GET", "cache/ignored-params")).json()

    problems = []
    if "values" not in left:
        problems.append("Clear the values of header '.' removed the header named 'values' instead")
    if not 200 <= cleared.status_code < 300:
        problems.append(f"Clear the values of header '.' answered {cleared.status_code}")
    if not 200 <= removed.status_code < 300:
        problems.append(f"Stop ignoring '.' answered {removed.status_code}")
    if "." in {str(item.get("name")) for item in still.get("items") or ()}:
        problems.append("the parameter '.' is still ignored after Stop ignoring")
    assert not problems, " | ".join(problems)


# ======================================================================================= esc-3 (JSON nesting)


# Fixed in the P11 review round (esc-3, shared fixer): a regression test now.
async def test_a_captured_body_of_nested_brackets_still_shows_its_request(
    page: Any,  # noqa: F811
    pages_app: Any,  # noqa: F811
) -> None:
    refused = await send(
        pages_app,
        "/wp-login.php",
        "203.0.113.182",
        method="POST",
        user_agent="DeepJson/1.0",
        body=b"[" * 16384,
        headers={"Content-Type": "application/json"},
    )
    assert refused.status_code == 404  # a probe: refused, so captured with its body (capture_max_body 16 KiB)
    await pages_app.flush()
    rows = (await page.api("GET", "live", params={"limit": 50})).json()
    ids = [item["request_id"] for item in rows["items"] if item.get("user_agent") == "DeepJson/1.0"]
    assert len(ids) == 1
    capture = await page.api("GET", f"live/{ids[0]}")
    assert capture.status_code == 200
    assert len(capture.json()["capture"]["request_body"]) == 16384

    drawer = await page.get("/admin/live/request", params={"id": ids[0]}, htmx=True)
    assert drawer.status_code == 200
    assert "data-card-error" not in drawer.text, "the request drawer failed to load"
    assert "DeepJson/1.0" in parse_html(drawer.text).text()


# ======================================================================================= esc-4 (line separators)


# Fixed in the P11 review round (esc-4, shared fixer): a regression test now.
async def test_unicode_line_separators_in_caller_text_never_make_extra_lines(
    page: Any,  # noqa: F811
    pages_app: Any,  # noqa: F811
) -> None:
    # The request filter tester, loaded from a recent request as the page offers it.
    rule = await page.api(
        "POST",
        "protection/header-rules",
        json={"needle": "x-review-injected", "scope": "key", "mode": "exact", "reason": "review esc-4"},
    )
    assert rule.status_code == 200, rule.text
    await pages_app.ctx.rules.reload()
    sneaky = ROBLOX_UA + " X-Review-Injected: 1"
    real = await send(pages_app, "/games.roblox.com/v1/games?universeIds=183", "203.0.113.183", user_agent=sneaky)
    assert real.status_code == 200  # the real request carried no header named x-review-injected: not refused
    await pages_app.flush()
    filters = parse_html((await page.fragment("protection", "request-filters")).text)
    samples = [
        option.get("value") or ""
        for option in filters.select("select[data-tester-sample] option")
        if "X-Review-Injected" in (option.get("value") or "")
    ]
    assert len(samples) == 1
    verdict = (await page.api("POST", "protection/header-rules/test", json={"headers": samples[0]})).json()

    # The audit entry of a cache rule written from the endpoint drawer of a template holding U+2028.
    served = await send(pages_app, "/games.roblox.com/v1/games/%E2%80%A8x/votes", "203.0.113.184")
    assert served.status_code == 200
    await pages_app.flush()
    endpoints = (await page.api("GET", "endpoints", params={"page_size": 250})).json()
    templates = [str(item.get("key")) for item in endpoints["items"] if " " in str(item.get("key"))]
    assert len(templates) == 1
    drawer = parse_html(
        (await page.get("/admin/cache/drawer/endpoint", params={"template": templates[0]}, htmx=True)).text
    )
    pattern = drawer.select_one('form[data-api-form] input[name="pattern"]').get("value")
    written = await page.api(
        "POST", "cache/rules", json={"pattern": pattern, "type": "glob", "ttl": 300, "reason": "review esc-4"}
    )
    assert written.status_code in (200, 201), written.text
    entry = parse_html((await page.fragment("audit", "entry", entry=written.json()["audit_id"])).text)
    lines = [row.text() for row in entry.select("tr.diff-lines__insert")]
    pattern_lines = [line for line in lines if '"pattern"' in line]

    problems = []
    if verdict["blocked"] is not False:
        problems.append(
            f"the tester reads {verdict['header_count']} headers and says a filter on a header the request "
            "never sent blocks it"
        )
    if not (len(pattern_lines) == 1 and "votes" in pattern_lines[0]):
        problems.append(f"the audit diff cut the pattern line: {lines}")
    assert not problems, " | ".join(problems)


# ======================================================================================= esc-5 (evidence links)


# Fixed in the P11 review round (esc-5, shared fixer): a regression test now.
async def test_place_evidence_links_carry_the_forged_place_as_one_encoded_value(tmp_path: Path) -> None:
    from insights import harness

    hostile_place = "1000000301&ip=203.0.113.9#spam"
    source = harness.FIXTURE_DIR / "place_heavy__one_place_dominates.yaml"
    data = yaml.safe_load(source.read_text(encoding="utf-8"))
    data["case"] = "review_hostile_place"
    data["profiles"]["place_301"]["place_id"] = hostile_place
    data["expect"] = {"fires": True}
    data["variants"] = []
    path = tmp_path / "place_heavy__review_hostile_place.yaml"
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    try:
        recs = await harness.run_case(str(path))
    finally:
        harness._close_all()
    mine = [rec for rec in recs if hostile_place in rec.subject or hostile_place in rec.title]
    assert len(mine) == 1, [rec.subject for rec in recs]
    links = [link for link in mine[0].evidence.links if link.startswith("/admin/clients")]
    assert links
    for link in links:
        parts = urlsplit(link)
        values = parse_qs(parts.query, keep_blank_values=True)
        assert parts.fragment == "", link
        assert len(values) == 1, link
        assert next(iter(values.values())) == [hostile_place], link
