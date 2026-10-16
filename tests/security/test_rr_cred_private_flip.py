"""A credential answer fetched under a `cache_private` grant is never coalesced, even when the cache and the upstream
read different rules (review lens cred, finding cred-4, fixed).

What this is
    A probe of plan 6.9 and 9.13 ("`cache_private=1` means never stored, never coalesced, never revalidated, never
    stale-served") against the fix of finding F2. The F2 fix (`cache/service.py: _private_to`) made a credential
    answer private only when the KEY is anonymous; it did not look at the grant the answer was fetched under.

Why it exists
    The cache decides the key (and whether to coalesce) from its own read of the endpoint policy at `peek`; the
    upstream routes with its own, later read. When the grant's `cache_private` changes in between (an admin adds an
    override marking an ALLOW_TOKEN endpoint private because its answer is per-request, exactly the case the switch
    exists for), the owner's credential answer is fetched under a private grant and must stay with its own
    request. Before the fix it was not stored but
    was still handed to every follower that joined the flight: the same-worker follower from the owner's objects
    (`_from_shared`), followers in other workers through the inline `shared` outcome.

How it works
    `confinement_harness.running_app` runs the real app. `games GET /v1/games` is ALLOW_TOKEN and shared in the
    shipped policy (D1 revised). The upstream's `fetch` is wrapped so the owner's call first waits (the second
    caller peeks and joins the flight meanwhile), then an `endpoint_policy_override` row (ALLOW_TOKEN,
    `cache_private=1`) is added through the audited rules service (this worker reloads at once), and only then
    routes. The cache now treats such an answer as `private` (`_private_to` honors the upstream's
    `UpstreamResult.private`, and `_row_now_private` reads the grant as it is when the answer arrives): the
    follower competes again and makes its own credential call (two cookie requests, both `MISS`, nothing
    stored).

What to read next
    `src/roxy/cache/service.py` (`_private_to`, `_row_now_private`, `_absorb`, `_serve_flight`),
    `src/roxy/upstream/service.py` (`_result`: `private`, `cacheable`), `src/roxy/cache/policy.py`
    (`request_policy`), and `tests/unit/cache/test_cache_flights.py` (the same rule for every follower path).
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest
from confinement_harness import PROBE_PATH, running_app

GAMES = "games.roblox.com"
ENDPOINT = "/v1/games"


async def test_answer_fetched_under_a_private_grant_is_never_coalesced(
    env: Any, credentials_dir: Path, fake_secrets: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    async with running_app(env, credentials_dir, fake_secrets, monkeypatch) as run:
        fixture = run.fixture()
        calls = {"n": 0}

        def games(record: Any) -> Any:
            calls["n"] += 1
            body = {"robux": "secret" if record.header("Cookie") else "anonymous", "call": calls["n"]}
            return fixture.MockResponse(body=json.dumps(body).encode(), delay_s=0.4)

        run.mock.routes[ENDPOINT] = games
        await run.activate_credential()
        shipped = run.ctx.rules.snapshot.credential_rule_for(f"{GAMES}{ENDPOINT}", "GET")
        assert shipped is not None
        assert not shipped.cache_private  # the shipped grant is shared: the second caller may join the flight
        real_fetch = run.ctx.upstream.fetch
        flipped: list[bool] = []

        async def flipping_fetch(req: Any, **kwargs: Any) -> Any:
            if not flipped:
                flipped.append(True)
                await asyncio.sleep(0.3)  # the other caller peeks (shared grant) and joins this flight meanwhile
                override = {"endpoint_id": "games:GET:/v1/games", "verdict": "ALLOW_TOKEN", "cache_private": True}
                await run.rule("endpoint_policy_override", override)
                rule = run.ctx.rules.snapshot.credential_rule_for(f"{GAMES}{ENDPOINT}", "GET")
                assert rule is not None
                assert rule.cache_private  # the upstream routes under the private grant
            return await real_fetch(req, **kwargs)

        monkeypatch.setattr(run.ctx.upstream, "fetch", flipping_fetch)
        run.clock.advance(5)
        responses = await asyncio.gather(run.get(f"/{GAMES}{ENDPOINT}"), run.get(f"/{GAMES}{ENDPOINT}"))
        states = sorted(response.headers.get("roxy-cache", "") for response in responses)
        cookie_calls = [r for r in run.cookie_requests() if r.path.split("?")[0] == ENDPOINT]
        assert flipped
        assert all(response.status_code == 200 for response in responses)
        assert all(r.path.split("?")[0] in (ENDPOINT, PROBE_PATH) for r in run.cookie_requests())
        assert all(json.loads(response.content)["robux"] == "secret" for response in responses)  # both credential
        assert ("COALESCED" in states, len(cookie_calls)) == (False, 2), states
        assert states == ["MISS", "MISS"]
        assert sorted(json.loads(response.content)["call"] for response in responses) == [1, 2]  # each its own
        await run.ctx.cache.settle()
        assert run.ctx.cache.stats.stores == 0  # never stored
        assert run.ctx.cache.stats.private == 2  # both answers stayed with their own request
