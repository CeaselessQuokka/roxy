"""Credential confinement through the whole app: what leaves Roxy with the cookie, for every kind of caller request.

What this is
    Adversarial probes for plan C1, C2 and owner decision D1 as revised on 2026-10-16 ("Roxy sends its own account
    with every request the endpoint policy marks ALLOW_TOKEN, and refuses BLOCK endpoints before Roblox"), run
    against the fully wired application with the REAL shipped endpoint policy and admin overrides written through
    the audited rules service. A battery of caller requests (every verb including HEAD and OPTIONS, path
    encodings of a granted and of a blocked endpoint, routing rules that prefer or force the rotator,
    `fallback_on_429`, 5xx answers, the CSRF retry on a credential POST and on an anonymous one, redirects
    followed by the upstream layer, stale-while-revalidate refreshes) runs with the credential active; then the
    overrides and category switches change the verdicts; then shadow mode; then the credential is rejected and
    cooling down. After each phase every request the mock Roblox received is checked, and every byte the recording
    proxy relayed is scanned.

Why it exists
    The per-layer tests (`test_credential_suite.py`, `test_endpoint_policy_bypass.py`, the upstream, cache and
    policy unit tests) each prove one defense. This module proves the composition: no path through router, abuse
    pipeline, endpoint policy, cache, single-flight, upstream routing, retries and redirects ends with the cookie on
    a request it should not be on, none sends it through the rotator, and a blocked endpoint never reaches Roblox.

How it works
    `confinement_harness.running_app` points direct and credential traffic at a loopback mock and rotator traffic
    through a loopback recording proxy (which marks the requests it relays with `X-Exit-Ip`). The mock answers by
    path; every path is unique across hosts, and `Host` names the Roblox host. The invariants checked on the
    mock's record (`cookie_problems`, `blocked_problems`):
      1. The cookie is the slot value, from the server IP (no `X-Exit-Ip`), on GET, HEAD or POST only, and only
         on an operation whose seed id the phase lists as ALLOW_TOKEN (`games GET /v1/games`, `users GET
         /v1/users/{userId}`, `users POST /v1/usernames/users`, ...), looked up with an independent copy of the
         seed's template index; a followed redirect hop carries it only when the hop's own target is listed
         (`via=hop-granted`). Roxy's own probe is the only other cookie request.
      2. A BLOCK operation (economy `/v1/user/currency`, auth `POST /v1/logout`, `users GET
         /v1/users/authenticated`, every PUT, PATCH and DELETE, every unknown POST) never reaches the mock in any
         spelling the URL parser accepts; in shadow mode (`endpoint_policy_enforce` off) it does, without the
         cookie.
      3. ALLOW_ANON operations (`users GET /v1/display-names/validate`, unknown GETs) reach the mock without it.
      4. Overrides and switches work end to end; 5. a rejected or cooling credential sends a fallback-capable
         grant anonymously and refuses a sign-in-only one without any call; with control.db unreadable at
         authorize time the cookie is never sent and a sign-in-only grant sends nothing at all
         (`test_shared_state_unavailable_never_uses_the_credential`).

What to read next
    `src/roxy/policy/engine.py`, `src/roxy/upstream/routing.py` and `service.py` (`_candidates`,
    `_redirect_url`), `src/roxy/egress/clients.py` (`_send_with`), `src/roxy/egress/credential.py`
    (`authorize`), and `tests/security/confinement_harness.py`.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import pytest
from confinement_harness import (
    ADMIN,
    PROBE_PATH,
    AppRun,
    leak_scan,
    running_app,
    test_leak_scan_is_not_vacuous,
)

from roxy.core.reasons import Egress
from roxy.policy.matcher import TemplateIndex
from roxy.policy.seed import load_seed
from roxy.rules.service import RuleValidationError

__all__ = ["test_leak_scan_is_not_vacuous"]  # collected here: the scanner's own self-check

SEED_INDEX = TemplateIndex(load_seed().rows)
"""An independent copy of the seed's template index: which seed operation a recorded request was."""

METHODS = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
BODY_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
GAMES = "games.roblox.com"
USERS = "users.roblox.com"
ECONOMY = "economy.roblox.com"
CURRENCY = "/v1/user/currency"  # economy GET: BLOCK (account currency)
LOGOUT = "/v1/logout"  # auth POST: BLOCK (ends the account's session)
LIST = "/v1/games"  # games GET: ALLOW_TOKEN, Roblox also answers it signed out (falls back)
DETAILS = "/v1/games/multiget-place-details"  # games GET: ALLOW_TOKEN, sign-in only (never falls back)
LOOKUP = "/v1/usernames/users"  # users POST: ALLOW_TOKEN batch read (falls back)
POLICIES = "/v1/groups/policies"  # groups POST: ALLOW_TOKEN, sign-in only
VALIDATE = "/v1/display-names/validate"  # users GET: ALLOW_ANON
BATCH = "/v1/assets/batch"  # assetdelivery POST: ALLOW_ANON

SHIPPED_TOKEN_IDS = frozenset(
    {
        "games:GET:/v1/games",
        "games:GET:/v1/games/multiget-place-details",
        "users:GET:/v1/users/{userId}",
        "users:POST:/v1/usernames/users",
        "groups:POST:/v1/groups/policies",
    }
)
"""The ALLOW_TOKEN operations this module's traffic touches (the shipped seed's verdicts)."""

BLOCKED_PREFIXES = {ECONOMY: "/v1/user/", "auth.roblox.com": "/v1/logout"}
"""Every caller request this module sends under these prefixes is BLOCK: in enforce mode the mock never sees one,
in any spelling (Roxy's own health probes reach other economy paths, anonymously)."""

# Caller paths: the granted endpoint in several encodings, the blocked one in several encodings (and two the URL
# parser refuses), Roxy's own probe endpoint, an ALLOW_ANON endpoint, granted endpoints that redirect (to a granted
# and to a blocked target), unknown anonymous endpoints that redirect INTO the granted one, a rotator-only unknown
# endpoint, POST batch reads (granted and anonymous, both with a CSRF challenge) and (last, so their cooldowns and
# breakers do not shape the others) a 429 and a 500.
PATHS = (
    f"/{GAMES}{LIST}?universeIds=1",
    "/GAMES.ROBLOX.COM/V1/GAMES?universeIds=2",
    f"/{GAMES}//v1//games/?universeIds=3",
    f"/{GAMES}/v1/%67ames?universeIds=4",
    f"/{ECONOMY}{CURRENCY}",
    "/ECONOMY.ROBLOX.COM/V1/USER/CURRENCY",
    f"/{ECONOMY}//v1//user/currency/",
    f"/{ECONOMY}/v1/user/%63urrency",
    f"/{ECONOMY}/v1/user/currency%2Fx",
    f"/{ECONOMY}/v1/user/%2e%2e/user/currency",
    f"/auth.roblox.com{LOGOUT}",
    f"/{USERS}{PROBE_PATH}",
    f"/{USERS}{VALIDATE}?displayName=a",
    f"/{USERS}/v1/users/301",
    f"/{USERS}/v1/users/302",
    f"/{GAMES}/v1/anon-redirect",
    f"/{GAMES}/v1/relative-redirect",
    f"/{GAMES}/v1/rotated?universeIds=1",
    f"/{USERS}{LOOKUP}",
    f"/assetdelivery.roblox.com{BATCH}",
    f"/{GAMES}/v1/rate-limited",
    f"/{GAMES}/v1/server-error",
)

ROUTING_RULES = (
    (f"{GAMES}{LIST}", "rotator_only"),  # must never push the credential through the rotator
    (f"{USERS}/v1/users/*", "prefer_rotator"),
    (f"{GAMES}/v1/anon-redirect", "rotator_only"),
    (f"{GAMES}/v1/rotated", "rotator_only"),
)


def seen_cookie(record: Any) -> Any:
    """An answer that tells the caller whether the mock saw the cookie."""
    body = {"seen": "cookie" if record.header("Cookie") else "anonymous", "path": record.path}
    return AppRun.fixture().MockResponse(body=json.dumps(body).encode())


def install_routes(run: AppRun) -> None:
    """The mock Roblox's answers, by path (module docstring)."""
    respond = run.fixture().MockResponse
    json_type = ("Content-Type", "application/json")

    def redirect(location: str, status: int = 302) -> Any:
        return respond(status=status, body=b"", headers=[("Location", location), json_type])

    def csrf(record: Any) -> Any:
        if not record.header("x-csrf-token"):
            return respond(
                status=403,
                body=b'{"errors":[{"code":0,"message":"Token Validation Failed"}]}',
                headers=[("x-csrf-token", "tok-confinement-probe"), json_type],
            )
        return seen_cookie(record)

    run.mock.routes.update(
        {
            LIST: seen_cookie,
            LIST + "/": seen_cookie,
            DETAILS: seen_cookie,
            CURRENCY: seen_cookie,
            LOGOUT: seen_cookie,
            VALIDATE: seen_cookie,
            "/v1/users/301": redirect(f"https://{GAMES}{LIST}?via=hop-granted"),
            "/v1/users/302": redirect(f"https://{ECONOMY}{CURRENCY}?via=hop-blocked"),
            "/v1/anon-redirect": redirect(f"https://{GAMES}{LIST}?via=anonredirect"),
            "/v1/relative-redirect": redirect(f"{LIST}?via=relredirect", 307),
            LOOKUP: csrf,
            POLICIES: csrf,
            BATCH: csrf,
            "/v1/rate-limited": respond(status=429, body=b'{"errors":[]}', headers=[("Retry-After", "1"), json_type]),
            "/v1/server-error": respond(status=500, body=b"oops", headers=[("Content-Type", "text/plain")]),
        }
    )


async def battery(run: AppRun) -> Counter[tuple[str, int]]:
    """Every path with every verb, each from its own client address. Returns (method, status) counts."""
    seen: Counter[tuple[str, int]] = Counter()
    for path in PATHS:
        for method in METHODS:
            # The app runs on a FakeClock: move it so the GCRA buckets (and short cooldowns) free up between
            # requests, as real time would. Otherwise later requests are only `upstream_busy` and prove nothing.
            run.clock.advance(5)
            kwargs: dict[str, Any] = {}
            if method in BODY_METHODS:
                kwargs = {"content": b'{"usernames":["a"]}', "headers": {"Content-Type": "application/json"}}
            response = await run.request(method, path, **kwargs)
            seen[(method, response.status_code)] += 1
    return seen


async def stale_while_revalidate(run: AppRun, path: str) -> None:
    """Cache `path`, let it expire into the SWR window, ask again, and wait for the background refresh."""
    await run.get(path)
    before = len(run.mock_requests())
    run.clock.advance(330)  # past the 300 s default lifetime, inside the 60 s stale-while-revalidate window
    response = await run.get(path)
    if response.headers.get("roxy-cache") == "REVALIDATING":
        assert await run.settle(lambda: len(run.mock_requests()) > before)
    await run.settle()


def host_of(record: Any) -> str:
    return (record.header("X-Roxy-Test-Host") or record.header("Host") or "").lower()


def operation_of(record: Any) -> str | None:
    """The seed id of a recorded request (HEAD as GET), or None for an operation the seed does not list."""
    row = SEED_INDEX.find(host_of(record), record.method, record.path.partition("?")[0])
    return row.id if row is not None else None


def cookie_problems(run: AppRun, token_ids: Iterable[str], records: list[Any] | None = None) -> list[str]:
    """Every mock request that carried the cookie where it must not (module docstring, invariant 1)."""
    allowed = frozenset(token_ids)
    problems: list[str] = []
    expected_cookie = f".ROBLOSECURITY={run.credential}"
    for record in run.cookie_requests() if records is None else [r for r in records if r.header("Cookie")]:
        path, _, query = record.path.partition("?")
        label = f"{record.method} {host_of(record)}{record.path[:80]}"
        if record.header("Cookie") != expected_cookie:
            problems.append(f"{label}: a cookie other than the slot value")
        if record.header("X-Exit-Ip"):
            problems.append(f"{label}: the cookie went through the rotator")
        if record.method not in ("GET", "HEAD", "POST"):
            problems.append(f"{label}: the cookie on a {record.method}")
        if (host_of(record), path) == (USERS, PROBE_PATH):
            if query:
                problems.append(f"{label}: the probe endpoint reached by a caller or a hop")
            continue
        if operation_of(record) not in allowed:
            problems.append(f"{label}: the cookie on {operation_of(record)}, not ALLOW_TOKEN in this phase")
        if "via=" in query and "via=hop-granted" not in query:
            problems.append(f"{label}: the cookie followed a redirect to a target without a grant")
    return problems


def blocked_problems(run: AppRun, records: list[Any] | None = None) -> list[str]:
    """Every mock request a BLOCK verdict must have stopped (module docstring, invariant 2)."""
    problems = []
    for record in run.mock_requests() if records is None else records:
        label = f"{record.method} {host_of(record)}{record.path[:80]}"
        prefix = BLOCKED_PREFIXES.get(host_of(record))
        if prefix is not None and (record.path.lower() + "/").startswith(prefix):
            problems.append(f"{label}: a blocked endpoint reached Roblox")
        if record.method in ("PUT", "PATCH", "DELETE"):
            problems.append(f"{label}: an unknown write reached Roblox")
        if record.method == "POST" and operation_of(record) is None:
            problems.append(f"{label}: an unknown POST reached Roblox")
        if (host_of(record), record.path) == (USERS, PROBE_PATH) and record.header("Cookie") is None:
            problems.append(f"{label}: a caller reached the account endpoint")
    return problems


def proxy_problems(run: AppRun) -> list[str]:
    run.proxy.wait_settled()
    recorded = run.proxy.all_recorded()
    problems = [f"rotator bytes: {item}" for item in leak_scan(recorded, run.credential)]
    if b".roblosecurity" in recorded.lower():
        problems.append("rotator bytes: the cookie name")
    return problems


def since(run: AppRun, before: int) -> list[Any]:
    return run.mock_requests()[before:]


def at(records: list[Any], path: str) -> list[Any]:
    return [r for r in records if r.path.split("?")[0] == path]


def callers(records: list[Any]) -> list[Any]:
    """The records of caller traffic: Roxy's own probe left out (`blocked_problems` proves no caller reached it)."""
    return [r for r in records if r.path != PROBE_PATH]


async def test_caller_traffic_carries_the_credential_only_for_allow_token_verdicts(
    env: Any, credentials_dir: Path, fake_secrets: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """C1, C2, D1 revised end to end, phase by phase (module docstring for the invariants)."""
    async with running_app(env, credentials_dir, fake_secrets, monkeypatch) as run:
        install_routes(run)
        # No scheduled liveness probe: the test moves the clock by hours, and a probe in the middle of a phase would
        # make a rejected credential active again behind the test's back.
        await run.settings(fallback_on_429=1, credential_probe_interval_min=0)
        for pattern, mode in ROUTING_RULES:
            await run.rule("rules_routing", {"pattern": pattern, "mode": mode})
        await run.activate_credential()

        # Phase 1, the shipped policy with the credential active.
        statuses = await battery(run)
        await stale_while_revalidate(run, f"/{GAMES}{LIST}?universeIds=5")
        await stale_while_revalidate(run, f"/{USERS}{VALIDATE}?displayName=swr")
        records = run.mock_requests()
        assert cookie_problems(run, SHIPPED_TOKEN_IDS) == []
        assert blocked_problems(run) == []
        assert proxy_problems(run) == []
        assert all(r.header("Cookie") for r in at(records, PROBE_PATH))  # only Roxy's own probe reached it
        # The credential really went where the policy grants it: GET (HEAD as GET), the POST batch read (after
        # its CSRF retry), the granted redirect hop. ALLOW_ANON endpoints went out, never with it.
        cookie_paths = {r.path.split("?")[0] for r in run.cookie_requests()}
        assert {LIST, LOOKUP, "/v1/users/301"} <= cookie_paths
        assert any("via=hop-granted" in r.path and r.header("Cookie") for r in records), "the granted hop"
        assert any(r.method == "POST" and r.header("Cookie") and r.header("x-csrf-token") for r in records)
        assert at(records, VALIDATE)
        assert at(records, BATCH)
        assert not any(r.header("Cookie") for r in at(records, VALIDATE) + at(records, BATCH))
        # The battery really exercised what it claims (otherwise the assertions above prove nothing).
        assert any("via=anonredirect" in r.path and not r.header("Cookie") for r in records), "anonymous redirect"
        assert any("via=relredirect" in r.path for r in records), "the relative redirect was not followed"
        assert not any("via=hop-blocked" in r.path for r in records), "a hop to a BLOCK endpoint was followed"
        assert any(r.header("x-csrf-token") and not r.header("Cookie") for r in records), "no anonymous CSRF retry"
        assert any(r.header("X-Exit-Ip") for r in records), "nothing went through the rotator"
        assert statuses[("OPTIONS", 204)] == len(PATHS)
        assert {status for (method, status) in statuses if method == "GET"} >= {200, 403, 404}
        blocked = await run.get(f"/{ECONOMY}{CURRENCY}?again=1")
        assert (blocked.status_code, blocked.headers.get("roxy-blocked")) == (403, "policy")
        assert blocked.headers.get("roxy-refusal") == "endpoint_policy"

        # Phase 2, overrides: ALLOW_ANON on a shipped ALLOW_TOKEN row removes the cookie, ALLOW_TOKEN on a shipped
        # ALLOW_ANON row adds it (GET only), an override never puts it on a write.
        await run.ctx.upstream.reset_state()
        anon_list = {"endpoint_id": "games:GET:/v1/games", "verdict": "ALLOW_ANON", "note": "probe"}
        token_validate = {"endpoint_id": "users:GET:/v1/display-names/validate", "verdict": "ALLOW_TOKEN"}
        await run.rule("endpoint_policy_override", anon_list)
        await run.rule("endpoint_policy_override", token_validate)
        with pytest.raises(RuleValidationError):
            await run.rule(
                "endpoint_policy_override",
                {"endpoint_id": "games:PATCH:/v1/games/{universeId}/user-votes", "verdict": "ALLOW_TOKEN"},
            )
        run.clock.advance(4000)  # every phase 1 cache entry is past its stale window
        before = len(run.mock_requests())
        phase2 = (SHIPPED_TOKEN_IDS - {"games:GET:/v1/games"}) | {"users:GET:/v1/display-names/validate"}
        for method in ("GET", "HEAD"):
            run.clock.advance(5)
            assert (await run.request(method, f"/{GAMES}{LIST}?phase=2")).status_code == 200
            run.clock.advance(5)
            assert (await run.request(method, f"/{USERS}{VALIDATE}?phase=2")).status_code == 200
        await battery(run)
        records = since(run, before)
        assert cookie_problems(run, phase2, records) == []
        assert blocked_problems(run, records) == []
        assert at(records, LIST)
        assert not any(r.header("Cookie") for r in at(records, LIST))  # the override took the account away
        assert any(r.header("Cookie") for r in at(records, VALIDATE))  # and gave it to the other endpoint

        # Phase 3, category switches: `strip_credential` on public-read takes the account off every row, overrides
        # included (it is the panic switch); `block_all` refuses the category before Roblox.
        await run.ctx.upstream.reset_state()
        await run.rules().delete("endpoint_policy_override", "games:GET:/v1/games", ADMIN, "probe")
        await run.rule("endpoint_policy_category", {"category": "public-read", "state": "strip_credential"})
        run.clock.advance(4000)
        before = len(run.mock_requests())
        for path in (f"{GAMES}{LIST}", f"{GAMES}{DETAILS}", f"{USERS}/v1/users/7", f"{USERS}{VALIDATE}"):
            run.clock.advance(5)
            assert (await run.get(f"/{path}?phase=3")).status_code == 200, path
        run.clock.advance(5)
        assert (await run.request("POST", f"/{USERS}{LOOKUP}", content=b"{}")).status_code == 200
        records = since(run, before)
        assert cookie_problems(run, set(), records) == []
        assert len(at(records, LIST)) == 1
        assert at(records, LOOKUP)
        assert at(records, VALIDATE)
        assert not any(r.header("Cookie") for r in at(records, VALIDATE))  # the switch beats the override
        await run.rules().update("endpoint_policy_category", "public-read", {"state": "block_all"}, ADMIN, "probe")
        before = len(run.mock_requests())
        for path in (f"{GAMES}{LIST}?phase=3b", f"{USERS}/v1/users/8"):
            run.clock.advance(5)
            response = await run.get(f"/{path}")
            assert (response.status_code, response.headers.get("roxy-blocked")) == (403, "policy"), path
        assert since(run, before) == []
        await run.rules().delete("endpoint_policy_category", "public-read", ADMIN, "probe")
        await run.rules().delete("endpoint_policy_override", "users:GET:/v1/display-names/validate", ADMIN, "probe")

        # Phase 4, shadow mode: a BLOCK verdict is not refused, and goes out WITHOUT the account.
        await run.settings(endpoint_policy_enforce=0)
        before = len(run.mock_requests())
        for method, path in (("GET", f"/{ECONOMY}{CURRENCY}?phase=4"), ("POST", f"/auth.roblox.com{LOGOUT}")):
            run.clock.advance(5)
            kwargs: dict[str, Any] = {"content": b"{}"} if method == "POST" else {}
            assert (await run.request(method, path, **kwargs)).status_code == 200, path
        records = since(run, before)
        assert len(at(records, CURRENCY)) == 1
        assert len(at(records, LOGOUT)) == 1
        assert not any(r.header("Cookie") for r in callers(records))
        await run.settings(endpoint_policy_enforce=1)

        # Phase 5, the credential rejected: a grant Roblox also answers signed out (identical_anonymous) goes out
        # anonymously, through the rotator when the routing rule says so; a sign-in-only grant gets no call at all.
        await run.ctx.upstream.reset_state()
        await run.ctx.egress.credential.mark_rejected("confinement probe")
        await credential_unusable_phase(run, "phase=5")
        assert not run.ctx.egress.tripped(Egress.DIRECT)
        assert not run.ctx.egress.tripped(Egress.ROTATOR)

        # Phase 6, the credential active again but cooling down after Roblox answered it 429: the same split.
        await run.ctx.upstream.reset_state()
        await run.activate_credential()
        # Roblox answers a sign-in-only credential request 429 (no anonymous retry can follow it).
        run.mock.routes[DETAILS] = run.fixture().MockResponse(
            status=429, body=b"{}", headers=[("Retry-After", "600"), ("Content-Type", "application/json")]
        )
        run.clock.advance(5)
        before = len(run.mock_requests())
        await run.get(f"/{GAMES}{DETAILS}?trigger=429")
        assert [bool(r.header("Cookie")) for r in at(since(run, before), DETAILS)] == [True]
        run.mock.routes[DETAILS] = seen_cookie
        await run.ctx.egress.credential.refresh()
        assert run.ctx.egress.credential.cooldown_remaining() > 0
        await credential_unusable_phase(run, "phase=6", advance_s=0)  # inside the 600 s cooldown
        assert run.ctx.egress.credential.cooldown_remaining() > 0
        assert proxy_problems(run) == []


async def credential_unusable_phase(run: AppRun, marker: str, *, advance_s: float = 4000) -> None:
    """While the credential cannot be used: fallback-capable grants answer anonymously, sign-in-only ones are
    refused without a call (invariant 5). `advance_s` moves earlier cache entries past their stale window."""
    run.clock.advance(advance_s)
    before = len(run.mock_requests())
    exits_before = sum(1 for r in run.mock_requests() if r.header("X-Exit-Ip"))
    for method in ("GET", "HEAD"):
        run.clock.advance(5)
        response = await run.request(method, f"/{GAMES}{LIST}?{marker}")
        assert response.status_code == 200, (method, response.status_code, response.headers.get("roxy-refusal"))
    run.clock.advance(5)
    assert (await run.request("POST", f"/{USERS}{LOOKUP}?{marker}", content=b"{}")).status_code == 200
    for method, path in (("GET", f"/{GAMES}{DETAILS}?{marker}"), ("POST", f"/groups.roblox.com{POLICIES}")):
        run.clock.advance(5)
        kwargs: dict[str, Any] = {"content": b"{}"} if method == "POST" else {}
        response = await run.request(method, path, **kwargs)
        assert response.status_code in (429, 503), (path, response.status_code, response.text[:200])
    records = since(run, before)
    assert not any(r.header("Cookie") for r in callers(records))
    assert at(records, LIST)
    assert at(records, LOOKUP)
    assert at(records, DETAILS) == []  # sign-in only: never sent anonymously
    assert at(records, POLICIES) == []
    assert sum(1 for r in run.mock_requests() if r.header("X-Exit-Ip")) > exits_before  # rotator_only on LIST
    assert proxy_problems(run) == []


async def test_rotator_only_rules_everywhere_never_carry_the_cookie(
    env: Any, credentials_dir: Path, fake_secrets: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A routing rule for every host that forces the rotator, with direct switched off: ALLOW_TOKEN requests still go
    out only on the credential client (server IP), and every other request goes out anonymously."""
    async with running_app(env, credentials_dir, fake_secrets, monkeypatch) as run:
        install_routes(run)
        await run.activate_credential()
        await run.settings(direct_enabled=0)
        # `cache_private`: every caller request makes its own credential call, so each one is checked.
        await run.rule(
            "endpoint_policy_override",
            {"endpoint_id": "games:GET:/v1/games", "verdict": "ALLOW_TOKEN", "cache_private": True},
        )
        for host in (GAMES, USERS, ECONOMY):
            await run.rule("rules_routing", {"pattern": host, "mode": "rotator_only"})
        for path in (f"/{GAMES}{LIST}", f"/{GAMES}/v1/anon-redirect", f"/{GAMES}/v1/x", f"/{USERS}{LOOKUP}"):
            for method in ("GET", "HEAD", "POST"):
                run.clock.advance(5)
                kwargs: dict[str, Any] = {"content": b"{}"} if method == "POST" else {}
                await run.request(method, path, **kwargs)
        assert cookie_problems(run, SHIPPED_TOKEN_IDS) == []
        assert blocked_problems(run) == []
        assert proxy_problems(run) == []
        assert len([r for r in run.cookie_requests() if r.path.split("?")[0] == LIST]) == 2  # GET and HEAD
        assert [r.method for r in run.cookie_requests() if r.path.split("?")[0] == LOOKUP] == ["POST", "POST"]
        assert any(r.header("X-Exit-Ip") for r in run.mock_requests())  # the anonymous ones used the rotator


def caller_cookie_paths(run: AppRun) -> list[str]:
    """The paths (no query) of every caller request the mock saw with the cookie (Roxy's own probe left out)."""
    return [r.path.split("?")[0] for r in run.cookie_requests() if r.path.split("?")[0] != PROBE_PATH]


async def test_a_grant_covers_exactly_its_operation(
    env: Any, credentials_dir: Path, fake_secrets: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Least privilege (finding F3, carried over to the policy): an ALLOW_TOKEN operation hands the cookie to the
    paths its template names and nothing else. A `{param}` is one segment; the paths below or beside a granted
    one are other operations with their own verdicts: unknown reads go out anonymously, a danger word blocks, and
    a literal BLOCK row beats the granted `{userId}` template next to it."""
    async with running_app(env, credentials_dir, fake_secrets, monkeypatch) as run:
        install_routes(run)
        await run.activate_credential()
        expected = {
            # (host, path): "cookie", "anonymous" or "blocked"
            (GAMES, LIST): "cookie",
            (GAMES, "/v1/gamesx"): "anonymous",
            (GAMES, "/v1/games/sneaky-new"): "anonymous",
            (GAMES, "/v1/games/history/transactions"): "blocked",
            (USERS, "/v1/users/5"): "cookie",
            (USERS, "/v1/users/5/unknown-sub"): "anonymous",
            (USERS, "/v1/users/5/x/y"): "anonymous",
            (USERS, PROBE_PATH): "blocked",
            (USERS, "/V1/USERS/AUTHENTICATED/"): "blocked",
        }
        outcome = {}
        for (host, path), want in expected.items():
            run.clock.advance(5)
            before = len(run.mock_requests())
            response = await run.get(f"/{host}{path}")
            records = since(run, before)
            if response.status_code == 403 and records == []:
                outcome[(host, path)] = "blocked"
            elif response.status_code == 200 and len(records) == 1:
                outcome[(host, path)] = "cookie" if records[0].header("Cookie") else "anonymous"
            else:
                outcome[(host, path)] = f"{response.status_code} after {len(records)} calls"
            assert outcome[(host, path)] == want, (host, path, outcome[(host, path)])
        assert sorted(caller_cookie_paths(run)) == sorted([LIST, "/v1/users/5"])
        assert proxy_problems(run) == []


async def test_an_unknown_read_promoted_by_an_override_gets_the_account_and_only_that_one(
    env: Any, credentials_dir: Path, fake_secrets: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """An operation Roblox does not document goes out without the account (unknown GET) or is blocked (unknown
    write). An admin can promote one unknown GET to ALLOW_TOKEN by its `unknown:<METHOD>:<template>` id: then that
    template, and no neighbor of it, carries the cookie; its writes stay blocked."""
    async with running_app(env, credentials_dir, fake_secrets, monkeypatch) as run:
        install_routes(run)
        await run.activate_credential()
        sneaky = f"/{GAMES}/v1/games/sneaky-new"
        run.clock.advance(5)
        assert (await run.get(sneaky + "?before=1")).status_code == 200
        assert caller_cookie_paths(run) == []
        await run.rule(
            "endpoint_policy_override",
            {"endpoint_id": f"unknown:GET:{GAMES}/v1/games/sneaky-new", "verdict": "ALLOW_TOKEN"},
        )
        for path in (sneaky + "?after=1", f"/{GAMES}/v1/games/sneaky-new/x", f"/{GAMES}/v1/games/sneaky-old"):
            run.clock.advance(5)
            assert (await run.get(path)).status_code == 200, path
        for method in ("PUT", "DELETE"):
            run.clock.advance(5)
            assert (await run.request(method, sneaky, content=b"{}")).status_code == 403, method
        assert caller_cookie_paths(run) == ["/v1/games/sneaky-new"]
        assert blocked_problems(run) == []
        assert proxy_problems(run) == []


PROXY_VARIABLES = ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "http_proxy", "all_proxy")


async def test_environment_proxies_are_never_honored_by_the_app(
    env: Any, credentials_dir: Path, fake_secrets: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """C2 item 2 through the app: with every proxy variable pointing at a recording trap (and NO_PROXY empty), the
    credential probe, an ALLOW_TOKEN credential request and anonymous direct traffic never touch the trap."""
    fixture = AppRun.fixture()
    with fixture.MockUpstream() as trap_target, fixture.RecordingProxy(upstream=trap_target.address) as trap:
        for name in PROXY_VARIABLES:
            monkeypatch.setenv(name, trap.url)
        monkeypatch.setenv("NO_PROXY", "")
        monkeypatch.setenv("no_proxy", "")
        async with running_app(env, credentials_dir, fake_secrets, monkeypatch) as run:
            install_routes(run)
            await run.activate_credential()
            for path in (f"/{GAMES}{LIST}?universeIds=1", f"/{USERS}{VALIDATE}?displayName=a"):
                run.clock.advance(5)
                assert (await run.get(path)).status_code == 200
            assert any(r.path.startswith(LIST) for r in run.cookie_requests())
            assert any(r.path.startswith(VALIDATE) and not r.header("Cookie") for r in run.mock_requests())
        trap.wait_settled()
        assert trap.exchanges == []
        assert trap_target.requests == []


async def test_shared_state_unavailable_never_uses_the_credential(
    env: Any, credentials_dir: Path, fake_secrets: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """C7: when control.db cannot be read right before the cookie would be attached, the credential is not used.
    A sign-in-only ALLOW_TOKEN operation is not sent anonymously instead (plan 6.9): the caller gets a 503 and
    nothing reaches Roblox (fail closed). An operation Roblox answers signed out (`identical_anonymous`) is sent
    the way it is whenever the account cannot take it: anonymously, never with the cookie."""
    from roxy.storage.db import SharedStateUnavailable

    async with running_app(env, credentials_dir, fake_secrets, monkeypatch) as run:
        install_routes(run)
        await run.activate_credential()
        before = len(run.mock_requests())

        async def unavailable(*args: Any, **kwargs: Any) -> Any:
            raise SharedStateUnavailable("control", "probe: disk gone")

        monkeypatch.setattr(run.ctx.dbs.control, "read", unavailable)
        run.clock.advance(5)
        response = await run.get(f"/{GAMES}{DETAILS}?c7=1")
        assert response.status_code == 503
        assert response.headers["roxy-refusal"] == "credential_unavailable"  # refused at authorize
        assert len(run.mock_requests()) == before  # neither with the cookie nor anonymously
        run.clock.advance(5)
        response = await run.get(f"/{GAMES}{LIST}?c7=1")
        assert response.status_code == 200
        assert json.loads(response.content)["seen"] == "anonymous"
        assert [r.header("Cookie") for r in since(run, before)] == [None]
