"""Final review, lens "pipeline": the request pipeline callers see (plan 7, 4.1 to 4.4, DESIGN 11.9).

What this is
    One reproduction per finding of `.remake/final_review/find_pipeline.md`. Each was a strict xfail until the
    final review fixed its finding; each is a regression test now, written to pass whatever reasonable shape the
    fix takes.

Why it exists
    The final review files only reproduced findings: a finding without a failing test is not a finding.

How it works
    Most tests drive the fully wired app of `tests/integration/test_pipeline_e2e.py` (real lifespan, temp databases,
    `respx` playing Roblox, a FakeClock). The upstream reset finding uses the signed-in admin API fixtures of
    `tests/integration/admin_api/conftest.py`, and the rotator finding uses the upstream unit doubles
    (`tests/unit/upstream/upstream_fakes.py`, loaded by path as the integration tests do).

What to read next
    `.remake/final_review/find_pipeline.md`, then `roxy/upstream/service.py`, `roxy/cache/service.py` and
    `roxy/proxy/respond.py`.
"""

from __future__ import annotations

import importlib.util
import sys
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from integration.admin_api.conftest import api, api_admin, api_app  # noqa: F401  (the signed-in admin fixtures)
from integration.test_pipeline_e2e import E2E, GAMES, GAMES_PATH, json_response, roxy_headers, running_app
from roxy.cache.policy import CacheSettings, StoreKind, request_policy, store_decision
from roxy.core.reasons import Egress
from roxy.rules.store import RulesSnapshot
from roxy.upstream.queue import Priority

TOO_MANY = {"errors": [{"code": 0, "message": "Too many requests"}]}
PRESENCE = "presence.roblox.com"
PRESENCE_PATH = "/v1/presence/users"


@pytest.fixture
async def e2e(env: Any, credentials_dir: Path, fake_secrets: dict[str, str], respx_mock: Any) -> AsyncIterator[E2E]:
    """The real app over temp databases, Roblox played by respx, the tarpit and the rotator off."""
    async with running_app(env, credentials_dir, fake_secrets, respx_mock) as harness:
        yield harness


def upstream_fakes() -> Any:
    """The upstream unit test doubles, loaded by path (tests are not a package)."""
    if "upstream_fakes" in sys.modules:
        return sys.modules["upstream_fakes"]
    path = Path(__file__).resolve().parents[1] / "unit" / "upstream" / "upstream_fakes.py"
    spec = importlib.util.spec_from_file_location("upstream_fakes", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["upstream_fakes"] = module
    spec.loader.exec_module(module)
    return module


# ============================================================================================ pipe-1: Content-Type


async def test_pipe_1_non_ascii_content_type_is_not_a_roxy_internal_error(e2e: E2E) -> None:
    """A POST whose Content-Type holds one byte above 0x7F is a caller mistake, never Roxy's own 500.

    `upstream/service.py _outbound_headers` copies `req.content_type` (the raw header) into the outbound request
    instead of using `scrub.forwarded_request_headers`, which keeps only printable ASCII. httpx refuses to encode the
    value, the exception becomes `internal_error`: 500 `"Internal Server Error"`, an ERROR log with a traceback, and a
    Roxy 5xx that feeds the caller 5xx alert (plan 17.7: 5 such requests in 10 minutes page the owner).
    """
    e2e.roblox.route(host=PRESENCE).mock(return_value=json_response({"data": []}))
    response = await e2e.request(
        "POST",
        f"/{PRESENCE}{PRESENCE_PATH}",
        content=b'{"userIds":[1]}',
        headers={"Content-Type": b"application/json; x=\xe9"},
    )
    assert response.status_code != 500, (response.status_code, response.content)
    assert e2e.last()["reason"] != "internal_error"


async def test_pipe_1_a_shared_cache_entry_never_hides_a_different_forwarded_content_type(e2e: E2E) -> None:
    """Plan 9.13 and `proxy/scrub.py`: every caller header forwarded upstream must vary the cache key.

    A Content-Type longer than 256 characters is dropped from the key's vary list by `scrub.is_safe_value`, but the
    upstream still sends it to Roblox. Roblox's answer to that body under that Content-Type is then stored under the
    key of the same body sent without a Content-Type (for which Roxy sends its own default), and served to those
    callers: a caller chooses what other callers of an allowlisted POST batch endpoint receive (a 400 is cached too).
    """
    seen: list[str | None] = []

    def roblox(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("content-type"))
        return json_response({"data": [len(seen)]})

    e2e.roblox.route(host=PRESENCE).mock(side_effect=roblox)
    url = f"/{PRESENCE}{PRESENCE_PATH}"
    # What Roblox receives for a body sent without a Content-Type (another body, so nothing is shared yet).
    plain = await e2e.request("POST", url, content=b'{"userIds":[2]}')
    assert plain.status_code == 200
    without_type = seen[-1]
    junk = "text/plain; x=" + "a" * 300  # printable, but longer than scrub.MAX_HEADER_VALUE
    first = await e2e.request("POST", url, content=b'{"userIds":[1]}', headers={"Content-Type": junk})
    if first.status_code != 200:
        # A fix may refuse an unusable Content-Type itself (the finding's optional 400): then Roblox never saw it and
        # nothing can be shared. Only a caller refusal before any upstream call counts as that fix.
        assert 400 <= first.status_code < 500, (first.status_code, first.content[:80])
        assert len(seen) == 1, seen
        return
    junk_seen = seen[-1]
    second = await e2e.request("POST", url, content=b'{"userIds":[1]}')
    shared = second.headers.get("roxy-cache") in ("HIT", "COALESCED")
    # Sharing the entry is only right when Roblox was asked exactly the same question both times.
    assert not shared or junk_seen == without_type, (junk_seen[:40] if junk_seen else junk_seen, without_type)


# ======================================================================================= pipe-2: path letter case


async def test_pipe_2_a_cooldown_holds_for_the_same_endpoint_in_other_letter_case(e2e: E2E) -> None:
    """Plan 7.5: "During a cooldown Roxy does not contact that endpoint through that egress at all."

    The cooldown key is `endpoint:<template>:direct`, and `metrics/templating.py template_for` keeps the path's letter
    case, so `/V1/Games` is another endpoint to Roxy while Roblox's routes ignore case. Each case variant reaches
    Roblox inside the Retry-After it just gave, gets its own endpoint bucket (bypassing the adaptive rate learned for
    the endpoint) and, at the third variant, escalates the cooldown to the whole host for every caller.
    """
    route = e2e.roblox.route(host=GAMES).mock(return_value=json_response(TOO_MANY, 429, **{"Retry-After": "60"}))
    first = await e2e.get(f"/{GAMES}{GAMES_PATH}?universeIds=1")
    assert first.status_code == 429
    assert route.call_count == 1
    variant = await e2e.get(f"/{GAMES}/V1/Games?universeIds=2")
    assert variant.status_code == 429
    assert roxy_headers(variant).get("roxy-refusal") == "upstream_cooldown"
    assert route.call_count == 1, "the same Roblox endpoint was called again inside its cooldown"


# ===================================================================================== pipe-4: compat and Roblox 429


async def test_pipe_4_compat_mode_collapses_a_roblox_429_like_every_other_roblox_4xx(e2e: E2E) -> None:
    """Plan 7.13 compat note: "every row whose status would be a 4xx from Roblox ... becomes 500", and the setting's
    own text: "Every Roblox 4xx, live or cached, reaches callers as a 500", "429 stays 429" only when it is off.
    v1 answered a Roblox 429 with 500 and Roblox's body (app/proxy.py `last_response`). With the setting on, v2
    still sends 429 with the busy text, which the old scripts the setting exists for do not understand."""
    await e2e.settings(compat_collapse_upstream_errors=1)
    e2e.route(GAMES, GAMES_PATH).mock(return_value=json_response(TOO_MANY, 429, **{"Retry-After": "30"}))
    response = await e2e.get(f"/{GAMES}{GAMES_PATH}?universeIds=1")
    assert response.status_code == 500, (response.status_code, response.content)
    assert "retry-after" in response.headers  # "Retry-After is still sent"


# =========================================================================== pipe-5: the upstream reset and markers


async def test_pipe_5_clearing_cooldowns_lets_the_marked_key_reach_roblox(
    api_app: Any,  # noqa: F811
    api: Any,  # noqa: F811
) -> None:
    """The Upstream page's "Clear cooldowns and breakers" dialog says every open cooldown ends at once, "so Roxy may
    call endpoints Roblox recently refused". `UpstreamService.reset_state` clears hot.db's cooldown and breaker rows,
    but the per-key 429 marker in the cache (plan 7.7, kept until the cooldown would have ended, up to
    `cooldown_max_s`) keeps answering that exact request with 429 `upstream_cooldown` without asking Roblox, while
    every other key of the endpoint is served: the owner's reset does not reach the hottest keys."""
    state = {"limited": True}

    def roblox(request: httpx.Request) -> httpx.Response:
        if state["limited"]:
            return json_response(TOO_MANY, 429, **{"Retry-After": "300"})
        return json_response({"data": ["fresh"]})

    route = api_app.roblox.route(host=GAMES, path=GAMES_PATH).mock(side_effect=roblox)
    caller = api_app.harness.new_client()
    headers = {"User-Agent": "Roblox/Linux", "X-Forwarded-For": "198.51.100.7"}
    url = f"/{GAMES}{GAMES_PATH}?universeIds=1"
    first = await caller.get(url, headers=headers)
    assert first.status_code == 429
    await api_app.ctx.cache.settle()
    reset = await api.post("upstream/reset", json={"reason": "Roblox recovered"})
    assert reset.status_code == 200, reset.text
    state["limited"] = False
    api_app.clock.advance(2)
    again = await caller.get(url, headers=headers)
    assert route.call_count == 2, ("the marked key never reached Roblox after the reset", roxy_headers(again))
    assert again.status_code == 200


# ======================================================================================= pipe-6: one rotator exit


async def test_pipe_6_one_burned_rotator_exit_does_not_park_the_key(dbs: Any) -> None:
    """Plan 7.5: a rotator 429 rotates the session, and the endpoint cools down only when
    `rotator_cooldown_distinct_exits` (3) exits returned 429: "one burned exit never parks all rotator use for an
    endpoint". Plan 7.7: the per-key marker lives "until the cooldown ends". After one exit's 429 there is no
    cooldown row, yet `UpstreamResult` carries `cooldown_s` and `negative_ttl_s` (Retry-After 45) and the cache
    policy stores a 429 marker for that long, so the key is refused for 45 s although the next exit would answer."""
    fakes = upstream_fakes()
    clock = fakes.SteppingClock()

    def answer(egress: Egress, out: Any) -> Any:
        if egress is Egress.ROTATOR:
            return fakes.answer(429, b'{"errors":[]}', {"retry-after": "45"})
        return fakes.answer()

    egress = fakes.FakeEgress(answer)
    rules = fakes.FakeRules()
    rules.route("games.roblox.com/v1/games", "rotator_only")
    settings = fakes.FakeSettings(rotator_enabled=1)
    ctx = fakes.make_ctx(dbs, clock, egress, settings=settings, rules=rules)
    service = fakes.make_service(ctx)
    result = await service.fetch(fakes.request(service), priority=Priority.INTERACTIVE, stale_available=False)
    assert result.upstream_status == 429
    assert fakes.read_rows(dbs.hot, "SELECT key FROM cooldown") == []  # one exit: no cooldown opened (plan 7.5)
    cs = CacheSettings.read(settings)
    policy = request_policy("GET", "games.roblox.com/v1/games", {}, cs, RulesSnapshot.empty())
    decision = store_decision(result, policy, cs)
    assert decision.kind is not StoreKind.MARKER, decision
