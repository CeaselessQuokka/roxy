"""The endpoint policy API (`/admin/api/v1/policy`, D1 revised 2026-10-16) in the real app.

What this is
    Tests of every route of `roxy/admin/api/policy.py` with the shipped seed and the real rules service: the guards
    (a session for reads, CSRF for writes), the summary, the category switches (tightening needs only the session,
    going back to Defaults a fresh second factor), the endpoints table (filters, search, sort, the whole table in a
    download), setting verdicts one at a time and in bulk (loosening needs a fresh factor, a risk 4 operation its
    typed path, ALLOW_TOKEN never on PUT, PATCH or DELETE), back to default, the reset of everything, the tester
    (blocked, sent with the account, sent without it, unknown, and the Friend server query guard), and the three
    logs of the range (unknown endpoints, caller sign-in attempts, shadow mode). Every change must reach the rules
    snapshot the proxy reads at once and leave an audit row with its reason.

Why it exists
    BRIEF.md section 8.3: loosening the policy sends Roxy's account (or more traffic) where it was not sent, so the
    API must judge every change the same way whichever client sends it.

What to read next
    `roxy/admin/api/policy.py`, `roxy/policy/engine.py`, `tests/integration/pages/test_page_policy.py`.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import pytest

from roxy.abuse.checks.endpoint_policy import POLICY_BLOCKED_EVENT, POLICY_UNKNOWN_EVENT, POLICY_WOULD_BLOCK_EVENT
from roxy.admin.api.policy import MAX_BULK
from roxy.policy.seed import CATEGORIES, load_seed

BLOCKED = "users:GET:/v1/users/authenticated"
TOKEN = "users:GET:/v1/users/{userId}"
TOKEN_TARGET = "users.roblox.com/v1/users/1"
LOGIN_ONLY = "thumbnails:GET:/v1/assets-thumbnail-3d"
ANON = "apis:GET:/toolbox-service/v2/assets/{id}"
LOGOUT = "auth:POST:/v2/logout"
PUT_ROW = "apis:PUT:/service-efficiency-api/v1/accounts/groups/{groupId}"
UNKNOWN_ID = "unknown:GET:games.roblox.com/v1/not-documented/{id}"
SERVERS = "games:GET:/v1/games/{placeId}/servers/{serverType}"


def _audit(api_app: Any, target: str) -> list[dict[str, Any]]:
    def read(conn: Any) -> list[dict[str, Any]]:
        rows = conn.execute("SELECT * FROM audit_log WHERE target = ? ORDER BY id", (target,)).fetchall()
        return [dict(row) for row in rows]

    rows: list[dict[str, Any]] = api_app.ctx.dbs.control.read_sync(read)
    return rows


def _policy(api_app: Any) -> Any:
    return api_app.ctx.rules.snapshot.endpoint_policy


async def _events(api_app: Any, kind: str, endpoint_id: str, verdict: str, count: int = 1) -> None:
    for _ in range(count):
        api_app.ctx.recorder.record_event(
            kind, "info", None, {"endpoint_id": endpoint_id, "verdict": verdict}, aggregate=True
        )
    api_app.clock.advance(60)  # counter events are written once their minute closes
    await api_app.ctx.recorder.flush()


# ================================================================================================= guards


@pytest.mark.parametrize(
    "path",
    [
        "policy",
        "policy/categories",
        "policy/endpoints",
        f"policy/endpoints/detail?id={BLOCKED}",
        "policy/test?target=users.roblox.com/v1/users/1",
        "policy/unknown",
        "policy/attempts",
        "policy/would-block",
    ],
)
async def test_every_read_needs_a_session(anon_api: Any, path: str) -> None:
    response = await anon_api.get(path)
    assert response.status_code == 401, (path, response.text)


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("PUT", "policy/endpoints", {"endpoint_id": TOKEN, "verdict": "BLOCK", "reason": "x"}),
        ("DELETE", "policy/endpoints", {"endpoint_id": TOKEN, "reason": "x"}),
        ("POST", "policy/reset", {"reason": "x"}),
        ("PUT", "policy/categories/ads", {"state": "block_all", "reason": "x"}),
    ],
)
async def test_every_write_needs_the_csrf_header(api: Any, method: str, path: str, body: dict[str, Any]) -> None:
    response = await api.request(method, path, json=body, csrf=False)
    assert response.status_code == 403, (method, path, response.text)


async def test_the_old_allowlist_api_is_gone(api: Any) -> None:
    for method, path in (("GET", "credential-allowlist"), ("POST", "credential-allowlist")):
        response = await api.request(method, path, json={"reason": "x"} if method == "POST" else None)
        assert response.status_code in (404, 405), (method, path, response.status_code)


# ================================================================================================= summary


async def test_summary_counts_settings_and_the_last_day(api_app: Any, api: Any, api_json: Any) -> None:
    seed = load_seed()
    answer = api_json(await api.get("policy"))
    assert answer["rows"] == answer["seed"]["operations"] == len(seed.rows)
    assert sum(answer["verdicts"].values()) == len(seed.rows)
    assert answer["verdicts"] == {
        verdict: sum(1 for row in seed.rows if row.verdict.value == verdict) for verdict in answer["verdicts"]
    }
    assert answer["overrides"] == 0
    assert answer["categories"] == {}
    assert answer["seed"]["generated_on"] == seed.generated_on
    assert set(answer["settings"]) >= {
        "endpoint_policy_enforce",
        "endpoint_policy_block_status",
        "endpoint_policy_block_message",
        "credential_enabled",
        "credential_bucket_per_min",
    }
    assert answer["last_24h"] == {
        "refused": 0,
        "unknown_requests": 0,
        "unknown_endpoints": 0,
        "would_block": 0,
        "auth_attempts": 0,
    }
    assert isinstance(answer["legacy_allowlist"], list)
    assert "fresh second factor" in answer["help"]["loosen"]
    await _events(api_app, POLICY_BLOCKED_EVENT, BLOCKED, "BLOCK", 3)
    await _events(api_app, POLICY_UNKNOWN_EVENT, UNKNOWN_ID, "ALLOW_ANON", 2)
    await _events(api_app, POLICY_WOULD_BLOCK_EVENT, BLOCKED, "BLOCK", 1)
    day = api_json(await api.get("policy"))["last_24h"]
    assert (day["refused"], day["unknown_requests"], day["unknown_endpoints"], day["would_block"]) == (3, 2, 1, 1)
    detail = api_json(await api.get("policy/endpoints/detail", params={"id": BLOCKED}))
    assert detail["refused_24h"] == 3


# ================================================================================================= categories


async def test_category_switches_tighten_freely_and_loosen_with_a_fresh_factor(
    api_app: Any, api: Any, api_json: Any, section13: Any
) -> None:
    listed = api_json(await api.get("policy/categories"))
    assert [item["key"] for item in listed["items"]] == list(CATEGORIES)
    public = next(item for item in listed["items"] if item["key"] == "public-read")
    assert public["states"] == ["defaults", "block_all", "strip_credential"]
    assert public["verdicts"] == public["default_verdicts"]
    ads = next(item for item in listed["items"] if item["key"] == "ads")
    assert ads["states"] == ["defaults", "block_all"]

    section13(await api.put("policy/categories/ads", json={"state": "block_all"}), 422, "validation_failed")
    section13(await api.put("policy/categories/nope", json={"state": "block_all", "reason": "x"}), 404, "not_found")
    api.make_mfa_stale()
    stripped = api_json(
        await api.put("policy/categories/public-read", json={"state": "strip_credential", "reason": "throttled"})
    )
    public = next(item for item in stripped["items"] if item["key"] == "public-read")
    assert public["state"] == "strip_credential"
    assert public["verdicts"]["ALLOW_TOKEN"] == 0
    assert api_app.ctx.rules.snapshot.credential_rule_for(TOKEN_TARGET, "GET") is None
    blocked = api_json(await api.put("policy/categories/public-read", json={"state": "block_all", "reason": "panic"}))
    assert next(i for i in blocked["items"] if i["key"] == "public-read")["verdicts"]["BLOCK"] == public["operations"]
    assert _policy(api_app).decide("users.roblox.com", "GET", "/v1/users/1").blocked

    # Back towards Defaults loosens: a fresh second factor first.
    section13(
        await api.put("policy/categories/public-read", json={"state": "strip_credential", "reason": "x"}),
        403,
        "reauth_required",
    )
    section13(
        await api.put("policy/categories/public-read", json={"state": "defaults", "reason": "x"}),
        403,
        "reauth_required",
    )
    await api.fresh_mfa()
    api_json(await api.put("policy/categories/public-read", json={"state": "defaults", "reason": "over"}))
    assert api_app.ctx.rules.snapshot.credential_rule_for(TOKEN_TARGET, "GET") is not None
    rows = _audit(api_app, "endpoint_policy_category:public-read")
    assert [row["reason"] for row in rows] == ["throttled", "panic", "over"]


# ================================================================================================= endpoints


@pytest.mark.parametrize(
    ("params", "check"),
    [
        ({"category": "ads"}, lambda item: item["category"] == "ads"),
        ({"verdict": "ALLOW_ANON"}, lambda item: item["verdict"] == "ALLOW_ANON"),
        ({"risk": 4}, lambda item: item["risk"] == 4),
        ({"method": "post"}, lambda item: item["method"] == "POST"),
        ({"auth": "cookie-required"}, lambda item: item["roblox_auth"] == "cookie-required"),
        ({"host": "Users.Roblox.com"}, lambda item: item["host"] == "users.roblox.com"),
        ({"q": "authenticated"}, lambda item: "authenticated" in json.dumps(item).lower()),
    ],
    ids=lambda value: "-".join(map(str, value)) if isinstance(value, dict) else "check",
)
async def test_the_endpoints_filters_and_search(api: Any, api_json: Any, params: dict[str, Any], check: Any) -> None:
    answer = api_json(await api.get("policy/endpoints", params={**params, "page_size": 250}))
    assert answer["total"] > 0
    assert all(check(item) for item in answer["items"])
    everything = api_json(await api.get("policy/endpoints"))["total"]
    assert answer["total"] < everything


async def test_the_endpoints_table_shape_sort_and_whole_download(api: Any, api_json: Any) -> None:
    answer = api_json(await api.get("policy/endpoints"))
    assert answer["total"] == len(load_seed().rows)
    assert len(answer["items"]) == 25
    item = answer["items"][0]
    for key in ("id", "method", "host", "path", "summary", "verdict", "verdict_words", "default_verdict", "risk"):
        assert key in item, key
    assert "domain_doc" in item
    assert "feature_doc" in item
    assert all(i["domain_doc"].startswith("https://create.roblox.com/") for i in answer["items"])
    assert {f["key"] for f in answer["filters"]["verdicts"]} == {"BLOCK", "ALLOW_TOKEN", "ALLOW_ANON"}
    risky = api_json(await api.get("policy/endpoints", params={"sort": "risk", "order": "desc"}))
    assert risky["items"][0]["risk"] == 4
    download = await api.get("policy/endpoints", params={"format": "json", "category": "ads"})
    assert download.status_code == 200, download.text[:200]
    rows = download.json()
    rows = rows["items"] if isinstance(rows, dict) else rows
    ads = api_json(await api.get("policy/endpoints", params={"category": "ads"}))["total"]
    assert len(rows) == ads > 0  # the whole filtered table, not the page on screen


async def test_put_one_tightens_without_a_fresh_factor_and_reaches_the_snapshot(
    api_app: Any, api: Any, api_json: Any, section13: Any
) -> None:
    section13(
        await api.put("policy/endpoints", json={"endpoint_id": TOKEN, "verdict": "BLOCK"}), 422, "validation_failed"
    )
    section13(
        await api.put("policy/endpoints", json={"endpoint_id": "users:GET:/nope", "verdict": "BLOCK", "reason": "x"}),
        422,
        "validation_failed",
    )
    section13(await api.put("policy/endpoints", json={"verdict": "BLOCK", "reason": "x"}), 422, "validation_failed")
    api.make_mfa_stale()
    done = api_json(
        await api.put(
            "policy/endpoints", json={"endpoint_id": TOKEN, "verdict": "BLOCK", "note": "noisy", "reason": "abuse"}
        )
    )
    assert done["changed"] == 1
    (item,) = done["endpoints"]
    assert (item["verdict"], item["default_verdict"], item["source"], item["override_note"]) == (
        "BLOCK",
        "ALLOW_TOKEN",
        "override",
        "noisy",
    )
    assert _policy(api_app).decide("users.roblox.com", "GET", "/v1/users/1").blocked
    assert api_app.ctx.rules.snapshot.credential_rule_for(TOKEN_TARGET, "GET") is None
    (row,) = _audit(api_app, f"endpoint_policy_override:{TOKEN}")
    assert row["reason"] == "abuse"
    changed = api_json(await api.get("policy/endpoints", params={"changed": "true"}))
    assert [i["id"] for i in changed["items"]] == [TOKEN]
    # ALLOW_TOKEN -> ALLOW_ANON is tightening too.
    api_json(
        await api.put("policy/endpoints", json={"endpoint_id": LOGIN_ONLY, "verdict": "ALLOW_ANON", "reason": "x"})
    )


async def test_loosening_needs_a_fresh_factor_and_never_puts_the_account_on_a_put(
    api_app: Any, api: Any, api_json: Any, section13: Any
) -> None:
    api.make_mfa_stale()
    loosen = {"endpoint_id": BLOCKED, "verdict": "ALLOW_ANON", "reason": "testing"}
    stale = await api.put("policy/endpoints", json=loosen)
    section13(stale, 403, "reauth_required")
    assert stale.headers.get("Roxy-Reauth")
    assert BLOCKED not in _policy(api_app).overrides
    await api.fresh_mfa()
    assert api_json(await api.put("policy/endpoints", json=loosen))["endpoints"][0]["verdict"] == "ALLOW_ANON"
    assert not _policy(api_app).decide("users.roblox.com", "GET", "/v1/users/authenticated").blocked
    token = {"endpoint_id": PUT_ROW, "verdict": "ALLOW_TOKEN", "reason": "never"}
    section13(await api.put("policy/endpoints", json=token), 422, "validation_failed")


async def test_a_risk_4_endpoint_is_loosened_alone_with_its_path_typed(
    api_app: Any, api: Any, api_json: Any, section13: Any
) -> None:
    body = {"endpoint_id": LOGOUT, "verdict": "ALLOW_ANON", "reason": "testing"}
    fields = section13(await api.put("policy/endpoints", json=body), 422, "confirm_required")
    assert "/v2/logout" in fields["confirm"]
    section13(await api.put("policy/endpoints", json=body | {"confirm": "/v2/LOGOUT"}), 422, "confirm_required")
    bulk = {"endpoint_ids": [LOGOUT, BLOCKED], "verdict": "ALLOW_ANON", "confirm": "/v2/logout", "reason": "x"}
    section13(await api.put("policy/endpoints", json=bulk), 422, "confirm_required")
    assert api_json(await api.put("policy/endpoints", json=body | {"confirm": "/v2/logout"}))["changed"] == 1
    # Tightening it again needs no confirmation.
    api_json(await api.put("policy/endpoints", json={"endpoint_id": LOGOUT, "verdict": "BLOCK", "reason": "back"}))


async def test_bulk_block_and_back_to_default(api_app: Any, api: Any, api_json: Any, section13: Any) -> None:
    ids = [TOKEN, ANON, SERVERS]
    api.make_mfa_stale()
    done = api_json(await api.put("policy/endpoints", json={"endpoint_ids": ids, "verdict": "BLOCK", "reason": "bulk"}))
    assert done["changed"] == 3
    assert {item["verdict"] for item in done["endpoints"]} == {"BLOCK"}
    too_many = {"endpoint_ids": [TOKEN] * (MAX_BULK + 1), "verdict": "BLOCK", "reason": "x"}
    section13(await api.put("policy/endpoints", json=too_many), 422, "validation_failed")
    # Back to default loosens these three (their defaults send them): a fresh factor first.
    section13(
        await api.delete("policy/endpoints", json={"endpoint_ids": ids, "reason": "undo"}), 403, "reauth_required"
    )
    await api.fresh_mfa()
    reset = api_json(await api.delete("policy/endpoints", json={"endpoint_ids": [*ids, BLOCKED], "reason": "undo"}))
    assert reset["reset"] == 3  # BLOCKED had no override: nothing to reset
    assert _policy(api_app).overrides == {}
    assert api_app.ctx.rules.snapshot.credential_rule_for(TOKEN_TARGET, "GET") is not None
    # Back to default that tightens (an override looser than the default) needs no fresh factor.
    api_json(await api.put("policy/endpoints", json={"endpoint_id": BLOCKED, "verdict": "ALLOW_ANON", "reason": "x"}))
    api.make_mfa_stale()
    assert api_json(await api.delete("policy/endpoints", json={"endpoint_id": BLOCKED, "reason": "y"}))["reset"] == 1


async def test_reset_all_needs_a_reason_and_a_fresh_factor(
    api_app: Any, api: Any, api_json: Any, section13: Any
) -> None:
    api_json(await api.put("policy/endpoints", json={"endpoint_id": TOKEN, "verdict": "BLOCK", "reason": "x"}))
    api_json(await api.put("policy/categories/ads", json={"state": "block_all", "reason": "x"}))
    section13(await api.post("policy/reset", json={}), 422, "validation_failed")
    api.make_mfa_stale()
    section13(await api.post("policy/reset", json={"reason": "clean"}), 403, "reauth_required")
    await api.fresh_mfa()
    answer = api_json(await api.post("policy/reset", json={"reason": "clean"}))
    assert (answer["overrides"], answer["categories"]) == (0, {})
    assert _policy(api_app).overrides == {}
    assert _policy(api_app).categories == {}
    assert _audit(api_app, f"endpoint_policy_override:{TOKEN}")[-1]["reason"] == "clean"


# ================================================================================================= the tester


@pytest.mark.parametrize(
    ("target", "method", "expect"),
    [
        ("https://users.roblox.com/v1/users/authenticated", "GET", {"verdict": "BLOCK", "known": True}),
        ("https://roxy.example.com/users.roblox.com/v1/users/1", "GET", {"verdict": "ALLOW_TOKEN", "known": True}),
        ("users.roblox.com/v1/users/1", "HEAD", {"verdict": "ALLOW_TOKEN", "endpoint_id": TOKEN}),
        ("apis.roblox.com/toolbox-service/v2/assets/9", "GET", {"verdict": "ALLOW_ANON", "credential": None}),
        ("games.roblox.com/v1/not-documented/5", "GET", {"verdict": "ALLOW_ANON", "known": False, "source": "unknown"}),
        ("games.roblox.com/v1/not-documented/5", "POST", {"verdict": "BLOCK", "known": False}),
        ("games.roblox.com/v1/my/settings", "GET", {"verdict": "BLOCK", "known": False}),
        ("games.roblox.com/v1/games/1818/servers/Friend", "GET", {"verdict": "BLOCK", "source": "guard"}),
        ("games.roblox.com/v1/games/1818/servers/1?limit=10", "GET", {"verdict": "BLOCK", "source": "guard"}),
        ("games.roblox.com/v1/games/1818/servers/Public", "GET", {"verdict": "ALLOW_TOKEN", "endpoint_id": SERVERS}),
    ],
)
async def test_the_tester(api: Any, api_json: Any, target: str, method: str, expect: dict[str, Any]) -> None:
    answer = api_json(await api.get("policy/test", params={"target": target, "method": method}))
    for key, value in expect.items():
        assert answer[key] == value, (key, answer)
    assert answer["refused"] is (answer["verdict"] == "BLOCK")  # enforced by default
    assert answer["shadow"] is False
    assert [step["step"] for step in answer["steps"]][:3] == ["Admin override", "Category switch", "Shipped verdict"]
    if answer["verdict"] == "ALLOW_TOKEN":
        assert answer["credential"] == {"cache_private": False, "anonymous_fallback": True}
    if not answer["known"]:
        assert answer["unknown_override_id"] == answer["endpoint_id"]
        assert answer["endpoint_id"].startswith("unknown:")


async def test_the_tester_fallback_shadow_and_bad_targets(
    api_app: Any, api: Any, api_json: Any, section13: Any
) -> None:
    login_only = api_json(
        await api.get("policy/test", params={"target": "thumbnails.roblox.com/v1/assets-thumbnail-3d"})
    )
    assert login_only["credential"] == {"cache_private": False, "anonymous_fallback": False}
    await api_app.settings(endpoint_policy_enforce=0)
    shadow = api_json(await api.get("policy/test", params={"target": "users.roblox.com/v1/users/authenticated"}))
    assert (shadow["refused"], shadow["shadow"]) == (False, True)
    for target in ("example.com/v1/users", "/", "https://roxy.example.com/v1/users"):
        section13(await api.get("policy/test", params={"target": target}), 422, "validation_failed")
    section13(await api.get("policy/test", params={"target": "x" * 3000}), 422, "validation_failed")


# ================================================================================================= unknown endpoints


async def test_unknown_endpoints_are_listed_and_get_a_verdict(
    api_app: Any, api: Any, api_json: Any, section13: Any
) -> None:
    await _events(api_app, POLICY_UNKNOWN_EVENT, UNKNOWN_ID, "ALLOW_ANON", 4)
    await _events(api_app, POLICY_UNKNOWN_EVENT, "unknown:POST:games.roblox.com/v1/write", "BLOCK", 1)
    listed = api_json(await api.get("policy/unknown"))
    assert listed["total"] == 2
    first = listed["items"][0]
    assert (first["endpoint_id"], first["verdict"], first["count"]) == (UNKNOWN_ID, "ALLOW_ANON", 4)
    assert "range" in listed
    assert "endpoint_id" in listed.get("caller_text", ["endpoint_id"])
    # Sending it with the account loosens (its rule says ALLOW_ANON): a fresh factor first.
    api.make_mfa_stale()
    body = {"endpoint_id": UNKNOWN_ID, "verdict": "ALLOW_TOKEN", "reason": "reviewed: public"}
    section13(await api.put("policy/endpoints", json=body), 403, "reauth_required")
    blocked = api_json(await api.put("policy/endpoints", json=body | {"verdict": "BLOCK"}))
    assert blocked["endpoints"][0] == {"id": UNKNOWN_ID, "verdict": "BLOCK", "default_verdict": "ALLOW_ANON"}
    assert _policy(api_app).decide("games.roblox.com", "GET", "/v1/not-documented/77").blocked
    await api.fresh_mfa()
    api_json(await api.put("policy/endpoints", json=body))
    assert api_app.ctx.rules.snapshot.credential_rule_for("games.roblox.com/v1/not-documented/77", "GET") is not None
    bad = {"endpoint_id": "unknown:GET:example.com/x", "verdict": "BLOCK", "reason": "x"}
    section13(await api.put("policy/endpoints", json=bad), 422, "invalid_rule")  # refused by the rules model
    reset = api_json(await api.delete("policy/endpoints", json={"endpoint_id": UNKNOWN_ID, "reason": "undo"}))
    assert reset["reset"] == 1


# ================================================================================================= logs


async def test_attempts_newest_first_never_the_value(api_app: Any, api: Any, api_json: Any, section13: Any) -> None:
    secret = "_|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in" + "B" * 600
    for value, real in ((secret, True), ("junk", False), (secret, True)):
        attempt = SimpleNamespace(kind="roblosecurity", where="cookie", name=".ROBLOSECURITY", value=value,
                                  looks_real=real)  # fmt: skip
        api_app.ctx.recorder.record_auth_attempt("203.0.113.7", attempt, method="GET", endpoint_id=TOKEN)
        api_app.clock.advance(1)
    await api_app.ctx.recorder.flush()
    answer = api_json(await api.get("policy/attempts"))
    assert answer["total"] == 3
    assert [item["looks_real"] for item in answer["items"]] == [True, False, True]
    assert answer["items"][0]["fingerprint"] == answer["items"][2]["fingerprint"] != answer["items"][1]["fingerprint"]
    assert answer["items"][0]["at_ms"] > answer["items"][1]["at_ms"]
    assert secret[30:90] not in json.dumps(answer)
    section13(await api.get("policy/attempts", params={"order": "asc"}), 422, "invalid_table_query")
    assert api_json(await api.get("policy"))["last_24h"]["auth_attempts"] == 3


async def test_would_block_lists_what_shadow_mode_let_through(api_app: Any, api: Any, api_json: Any) -> None:
    await _events(api_app, POLICY_WOULD_BLOCK_EVENT, BLOCKED, "BLOCK", 2)
    await _events(api_app, POLICY_WOULD_BLOCK_EVENT, LOGOUT, "BLOCK", 5)
    answer = api_json(await api.get("policy/would-block"))
    assert [(item["endpoint_id"], item["count"]) for item in answer["items"]] == [(LOGOUT, 5), (BLOCKED, 2)]
    searched = api_json(await api.get("policy/would-block", params={"q": "logout"}))
    assert searched["total"] == 1
    download = await api.get("policy/would-block", params={"format": "csv"})
    assert download.status_code == 200
    assert LOGOUT in download.text
