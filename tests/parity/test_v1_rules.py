"""v1 parity: endpoint blocks, endpoint rate rules, request filters and User-Agent rules, end to end.

What this is
    Ports of the v1 smoke checks that drive a rule through the admin API and then prove its effect on a proxied
    request: S005 (lines 238 to 242), S010 (wildcard blocks), S011 (wildcard rate rule), S012, S019 and S032
    (request filters), S018 (regex blocks), S071 (the request filter tester), S079 (rules with their own reply),
    S094 (a User-Agent burst rule and its hit counts) and S096 and S097 (User-Agent rule scope, editing, the off
    switch and validation).

Why it exists
    The v2 unit tests prove each check on a fake request, and the admin API tests prove the CRUD routes; v1's suite
    proved the two together: a rule saved by the dashboard changes what the next caller gets, deleting it undoes
    that, and a refused request never reaches Roblox. These tests keep that end-to-end promise.

How it works
    The `parity` fixture runs the real app with Roblox played by respx. An admin signs in through the real login;
    rules are created and deleted with the admin API (so the worker's rule snapshot reloads as in production), and
    each proxied request comes from its own client address so the per-IP limit never interferes.

What to read next
    `roxy/admin/api/protection.py` (the routes), `roxy/abuse/checks/` (the checks) and `roxy/rules/match.py`
    (the shared matcher, v1 semantics).
"""

from __future__ import annotations

import json
from typing import Any

import httpx

RUNG1 = "Too many requests; please slow down."
BLOCKED = b'"This endpoint is currently blocked."\n'


def wire(text: str) -> bytes:
    """v1's refusal wire form: a JSON string plus a newline (Flask jsonify)."""
    return (json.dumps(text) + "\n").encode()


def ok(response: httpx.Response) -> Any:
    assert response.status_code in (200, 201), response.text
    return response.json()


def upstream(parity: Any, host: str) -> Any:
    """A respx route answering every path of `host` with 200 `{"ok":true}` (v1's fake upstream)."""
    return parity.roblox.route(host=host).mock(return_value=httpx.Response(200, json={"ok": True}))


async def test_v1_endpoint_blocks_glob_and_regex_from_save_to_delete(parity: Any) -> None:
    """v1 smoke lines 238 to 242 (S005), 459 to 476 (S010) and 731 to 744 (S018)."""
    admin = await parity.admin()
    games = upstream(parity, "games.roblox.com")
    glob = ok(await admin.post("protection/endpoint-blocks", json={"pattern": "/Games.Roblox.com/v1/games/*/servers"}))
    regex = ok(
        await admin.post(
            "protection/endpoint-blocks", json={"pattern": r"games\.roblox\.com/v1/games/\d+/votes", "type": "regex"}
        )
    )
    listed = {item["pattern"]: item for item in ok(await admin.get("protection/endpoint-blocks"))["items"]}
    assert "games.roblox.com/v1/games/*/servers" in listed  # stored normalized (v1 line 468)
    assert listed[r"games\.roblox\.com/v1/games/\d+/votes"]["type"] == "regex"  # never lowercased (v1 line 741)

    for path in ("/games.roblox.com/v1/games/694768217/servers/0", "/games.roblox.com/v1/games/123/servers"):
        response = await parity.get(path)
        assert response.status_code == 403, path  # `*` is one segment and a sub-path is always covered
        assert response.content == BLOCKED
        assert response.headers["roxy-blocked"] == "True"
    refused = await parity.get("/games.roblox.com/v1/games/999/votes")
    assert refused.status_code == 403
    assert games.call_count == 0  # a blocked request never reaches Roblox (v1 lines 460 and 736)
    sibling = await parity.get("/games.roblox.com/v1/games/9583680112/badges")
    assert sibling.status_code == 200
    assert games.call_count == 1
    parity.clock.advance(61)
    await parity.ctx.recorder.flush()
    attempts = {item["path"]: item for item in ok(await admin.get("protection/endpoint-blocks/attempts"))["items"]}
    assert attempts["games.roblox.com/v1/games/999/votes"]["attempts"] == 1  # the refused path is logged (row 75)
    assert attempts["games.roblox.com/v1/games/999/votes"]["clients"] == 1

    ok(await admin.delete(f"protection/endpoint-blocks/{glob['key']}"))
    ok(await admin.delete(f"protection/endpoint-blocks/{regex['key']}"))
    assert (await parity.get("/games.roblox.com/v1/games/694768217/servers/0")).status_code == 200
    assert (await parity.get("/games.roblox.com/v1/games/999/votes")).status_code == 200
    assert games.call_count == 3


async def test_v1_wildcard_endpoint_rule_counts_per_ip_and_pattern(parity: Any) -> None:
    """v1 smoke lines 487 to 490 (S011): rule `thumbnails.roblox.com/v1/*/icons`, limit 1 per hour."""
    admin = await parity.admin()
    upstream(parity, "thumbnails.roblox.com")
    ok(
        await admin.post(
            "protection/endpoint-rules",
            json={"pattern": "thumbnails.roblox.com/v1/*/icons", "limit": 1, "period": 3600},
        )
    )
    ip = parity.ip()
    assert (await parity.get("/thumbnails.roblox.com/v1/users/icons?size=150", ip=ip)).status_code == 200
    second = await parity.get("/thumbnails.roblox.com/v1/users/icons?size=420", ip=ip)  # another query, same rule
    assert second.status_code == 429
    assert second.headers["roxy-endpoint-limited"] == "True"
    assert (await parity.get("/thumbnails.roblox.com/v1/groups/thumbnails?id=1", ip=ip)).status_code == 200


async def test_v1_rules_carry_their_own_reply_and_keep_their_note_private(parity: Any) -> None:
    """v1 smoke lines 2499 to 2515 (S079): a block and a rate rule answer with their own message."""
    admin = await parity.admin()
    upstream(parity, "economy.roblox.com")
    upstream(parity, "avatar.roblox.com")
    message = "Deprecated: use games.roblox.com/v1/games/*/votes instead."
    ok(
        await admin.post(
            "protection/endpoint-blocks",
            json={"pattern": "economy.roblox.com/v1/votingservice", "note": "legacy", "message": message},
        )
    )
    blocked = await parity.get("/economy.roblox.com/v1/votingservice/1234")
    assert blocked.status_code == 403
    assert blocked.content == wire(message)
    assert b"legacy" not in blocked.content  # the private note never reaches the caller
    ok(
        await admin.post(
            "protection/endpoint-rules",
            json={"pattern": "avatar.roblox.com", "limit": 1, "period": 60, "message": "Batch your avatar lookups."},
        )
    )
    ip = parity.ip()
    assert (await parity.get("/avatar.roblox.com/v1/users/1/avatar", ip=ip)).status_code == 200
    limited = await parity.get("/avatar.roblox.com/v1/users/2/avatar", ip=ip)
    assert limited.status_code == 429
    assert limited.content == wire("Batch your avatar lookups.")


async def test_v1_request_filters_by_name_value_regex_and_named_header(parity: Any) -> None:
    """v1 smoke lines 499 to 550 (S012), 750 to 757 (S019) and 1040 to 1052 (S032)."""
    admin = await parity.admin()
    games = upstream(parity, "games.roblox.com")
    xeno = ok(await admin.post("protection/header-rules", json={"needle": "xeno", "scope": "either"}))
    by_name = await parity.get("/games.roblox.com/v1/games?u=1", headers={"Xeno-Fingerprint": "9b6c6e24"})
    assert by_name.status_code == 429
    assert by_name.content == wire(RUNG1)  # disguised as a plain throttle: nothing names the filter
    assert b"eader" not in by_name.content.lower()
    assert b"xeno" not in by_name.content.lower()
    assert by_name.headers["roxy-throttled"] == "True"
    by_value = await parity.get("/games.roblox.com/v1/games?u=2", headers={"User-Agent": "Xeno/1.3.55"})
    assert by_value.status_code == 429
    assert games.call_count == 0
    clean = await parity.get("/games.roblox.com/v1/games?u=3", headers={"User-Agent": "Roblox/WinInet"})
    assert clean.status_code == 200
    assert games.call_count == 1

    ok(await admin.post("protection/header-rules", json={"needle": "exploit-guid", "scope": "key", "mode": "exact"}))
    assert (await parity.get("/games.roblox.com/v1/games?u=4", headers={"Exploit-Guid": "x"})).status_code == 429
    longer = await parity.get("/games.roblox.com/v1/games?u=5", headers={"Exploit-Guid-Extra": "x"})
    assert longer.status_code == 200  # an exact name never matches a longer one

    ok(await admin.delete(f"protection/header-rules/{xeno['key']}"))
    assert (
        await parity.get("/games.roblox.com/v1/games?u=6", headers={"User-Agent": "Xeno/1.3.55"})
    ).status_code == 200

    ok(
        await admin.post(
            "protection/header-rules", json={"needle": "Synapse|Xeno|KRNL", "scope": "value", "mode": "regex"}
        )
    )
    assert (await parity.get("/games.roblox.com/v1/games?u=7", headers={"User-Agent": "KRNL/2.0"})).status_code == 429
    legit = await parity.get("/games.roblox.com/v1/games?u=8", headers={"User-Agent": "LegitClient/1.0"})
    assert legit.status_code == 200
    invalid = await admin.post("protection/header-rules", json={"needle": "([bad", "scope": "value", "mode": "regex"})
    assert invalid.status_code == 422  # refused, never stored (v1 answered 400; DESIGN 13 says 422)

    named = ok(
        await admin.post(
            "protection/header-rules", json={"needle": "BadClient", "header": "User-Agent", "mode": "contains"}
        )
    )
    assert named["item"]["header"].lower() == "user-agent"
    assert (
        await parity.get("/games.roblox.com/v1/games?u=9", headers={"User-Agent": "BadClient/1.0"})
    ).status_code == 429
    elsewhere = await parity.get(
        "/games.roblox.com/v1/games?u=10", headers={"User-Agent": "Good/1.0", "X-Note": "BadClient is here"}
    )
    assert elsewhere.status_code == 200  # only the named header is examined
    assert games.call_count == 5
    parity.clock.advance(61)
    await parity.ctx.recorder.flush()
    attempts = ok(await admin.get("protection/header-rules/attempts"))
    assert sum(item["attempts"] for item in attempts["items"]) == 5  # every filtered request is logged (row 75)


async def test_v1_request_filter_tester_reads_pasted_text_and_never_saves_a_draft(parity: Any) -> None:
    """v1 smoke lines 2162 to 2205 (S071): the dry-run tester."""
    admin = await parity.admin()
    upstream(parity, "games.roblox.com")
    ok(await admin.post("protection/header-rules", json={"needle": "Xeno", "scope": "either"}))
    sample = "User-Agent: Roblox/WinInet\nXeno-Fingerprint: abc123\nAccept: */*"
    result = ok(await admin.post("protection/header-rules/test", json={"headers": sample}))
    assert result["blocked"] is True
    assert result["rules"][0]["matched_header"] == "Xeno-Fingerprint"
    assert result["rules"][0]["matched_field"] == "key"
    clean = ok(await admin.post("protection/header-rules/test", json={"headers": {"User-Agent": "Roblox/WinInet"}}))
    assert clean["blocked"] is False
    draft = {"header": "User-Agent", "needle": "wininet"}
    tried = ok(await admin.post("protection/header-rules/test", json={"headers": sample, "draft": draft}))
    assert tried["draft"]["matched"] is True  # case-insensitive, like the real match
    rules = ok(await admin.get("protection/header-rules"))["items"]
    assert [rule["needle"] for rule in rules] == ["Xeno"]  # testing a draft saved nothing
    bad = ok(
        await admin.post(
            "protection/header-rules/test", json={"headers": sample, "draft": {"needle": "([unclosed", "mode": "regex"}}
        )
    )
    assert bad["draft"]["valid"] is False  # explained, no crash
    empty = await admin.post("protection/header-rules/test", json={"headers": ""})
    assert empty.status_code == 422
    assert "Add at least one header to test against" in empty.text
    pasted = ok(
        await admin.post(
            "protection/header-rules/test", json={"headers": "GET /v1/users HTTP/1.1\n\nUser-Agent: Xeno-Loader"}
        )
    )
    assert pasted["header_count"] == 1  # the request line and the blank line are skipped
    assert pasted["blocked"] is True
    proxied = await parity.get("/games.roblox.com/v1/games?u=1", headers={"Xeno-Fingerprint": "abc"})
    assert proxied.status_code == 429  # the tester agrees with the proxy


async def test_v1_user_agent_rules_edit_in_place_global_scope_and_off_switch(parity: Any) -> None:
    """v1 smoke lines 3029 to 3050 (S096), 3075 and 3077 (S097)."""
    admin = await parity.admin()
    upstream(parity, "games.roblox.com")
    created = ok(await admin.post("protection/ua-rules", json={"needle": "SlowBot", "kind": "cooldown", "cooldown": 1}))
    edited = ok(
        await admin.patch(
            f"protection/ua-rules/{created['key']}",
            json={"needle": "RotatingBot", "kind": "burst", "limit": 1, "period": 60, "scope": "global"},
        )
    )
    assert edited["key"] == created["key"]  # edited in place, same id
    rules = ok(await admin.get("protection/ua-rules"))["items"]
    assert len(rules) == 1
    assert (rules[0]["kind"], rules[0]["limit"], rules[0]["scope"]) == ("burst", 1, "global")
    bot = {"User-Agent": "RotatingBot/3.1"}
    assert (await parity.get("/games.roblox.com/v1/games?u=1", headers=bot)).status_code == 200
    second_ip = await parity.get("/games.roblox.com/v1/games?u=2", headers=bot)
    assert second_ip.status_code == 429  # one budget for every address
    assert second_ip.headers["roxy-client-limited"] == "True"
    ok(await admin.patch(f"protection/ua-rules/{created['key']}", json={"enabled": False}))
    assert (await parity.get("/games.roblox.com/v1/games?u=3", headers=bot)).status_code == 200
    empty = await admin.post("protection/ua-rules", json={"needle": "", "kind": "burst", "limit": 2})
    assert empty.status_code == 422
    zero = await admin.post("protection/ua-rules", json={"needle": "Zero", "kind": "cooldown", "cooldown": 0})
    assert zero.status_code == 422


async def test_v1_user_agent_burst_rule_refuses_with_its_message_and_counts_its_hits(parity: Any) -> None:
    """v1 smoke lines 2984 to 3001 (S094): burst 2 per 60 s, then refuse with the rule's own message."""
    admin = await parity.admin()
    upstream(parity, "games.roblox.com")
    rule = ok(
        await admin.post(
            "protection/ua-rules",
            json={
                "needle": "GreedyScraper",
                "mode": "contains",
                "kind": "burst",
                "limit": 2,
                "period": 60,
                "message": "Please slow down, GreedyScraper.",
                "note": "friendly but fast",
            },
        )
    )
    assert rule["key"]
    bot = {"User-Agent": "GreedyScraper/1.0"}
    ip = parity.ip()
    answers = [await parity.get(f"/games.roblox.com/v1/games?u={n}", ip=ip, headers=bot) for n in range(4)]
    assert [response.status_code for response in answers] == [200, 200, 429, 429]  # no +1 leak
    assert answers[2].content == wire("Please slow down, GreedyScraper.")
    assert int(answers[2].headers["retry-after"]) > 0
    assert answers[2].headers["roxy-client-limited"] == "True"
    other = await parity.get("/games.roblox.com/v1/games?u=9", headers={"User-Agent": "Roblox/Linux"})
    assert other.status_code == 200
    parity.clock.advance(61)
    await parity.ctx.recorder.flush()
    rows = {item["id"]: item for item in ok(await admin.get("protection/ua-rules"))["items"]}
    assert rows[rule["key"]]["allowed"] == 2
    assert rows[rule["key"]]["refused"] >= 2
