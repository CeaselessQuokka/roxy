"""Credential confinement through the whole app: what leaves Roxy with the cookie, for every kind of caller request.

What this is
    Adversarial probes for plan C1, C2 and owner decision D1 ("never send the credential for callers"), run
    against the fully wired application. A battery of caller requests (every verb including HEAD and OPTIONS,
    path encodings that normalize to an allowlisted endpoint, routing rules that prefer or force the rotator,
    `fallback_on_429`, 5xx retries, the CSRF retry, redirects followed by the upstream layer, stale-while-revalidate
    refreshes) runs first with the credential active and the allowlist empty (D1 as shipped), then with two
    allowlist rows, then with `identical_anonymous` and a rejected credential. After each phase every request the
    mock Roblox received with a `Cookie` header is checked, and every byte the recording proxy relayed is scanned.

Why it exists
    The per-layer tests (`test_credential_suite.py`, the upstream and cache unit tests) each prove one defense.
    This module proves the composition: no path through router, abuse pipeline, cache, single-flight, upstream
    routing, retries and redirects ends with the cookie on a request it should not be on, and none sends it
    through the rotator. Each assertion fails if one of those invariants breaks.

How it works
    `confinement_harness.running_app` points direct and credential traffic at a loopback mock and rotator traffic
    through a loopback recording proxy (which marks the requests it relays with `X-Exit-Ip`). The mock answers by
    path: an allowlisted endpoint that tells the caller whether it saw the cookie, redirects (carrying `via=` in
    the target query so a followed hop is recognizable), a CSRF challenge, a 429 and a 500. A request "may" carry
    the cookie only when it is a GET to an allowlisted endpoint (or Roxy's own probe), straight from the server
    (no `X-Exit-Ip`), never a redirect hop. `test_allowlist_row_grants_only_its_endpoint` documents finding F3
    (strict xfail until the lead decides).

What to read next
    `src/roxy/upstream/routing.py` and `service.py` (`_candidates`, `_redirect_url`), `src/roxy/egress/clients.py`
    (`_send_with`), `src/roxy/egress/credential.py` (`authorize`), and `tests/security/confinement_harness.py`.
"""

from __future__ import annotations

import json
from collections import Counter
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

__all__ = ["test_leak_scan_is_not_vacuous"]  # collected here: the scanner's own self-check

METHODS = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
BODY_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
ECONOMY = "economy.roblox.com"
CURRENCY = "/v1/user/currency"

# Caller paths: the allowlisted endpoint in several encodings, an allowlisted endpoint that redirects, anonymous
# endpoints that redirect INTO the allowlisted one, a rotator-only endpoint, refused encodings, and (last, so
# their cooldowns and breakers do not shape the others) a 429, a 500 and a CSRF challenge.
PATHS = (
    f"/{ECONOMY}{CURRENCY}",
    "/ECONOMY.ROBLOX.COM/V1/USER/CURRENCY",
    f"/{ECONOMY}.{CURRENCY}",
    f"/{ECONOMY}//v1//user/currency/",
    f"/{ECONOMY}/v1/user/%63urrency",
    f"/{ECONOMY}{CURRENCY}?prettyprint=true&x=1",
    f"/{ECONOMY}/v1/user/currency%2Fx",
    f"/{ECONOMY}/v1/user/%2e%2e/user/currency",
    f"/{ECONOMY}/v1/user/hop",
    f"/{ECONOMY}/v1/user/hop?to=games",
    f"/{ECONOMY}/v1/redirect-to-currency",
    f"/{ECONOMY}/v1/relative-redirect",
    "/games.roblox.com/v1/rotated?universeIds=1",
    f"/{ECONOMY}/v1/csrf",
    f"/{ECONOMY}/v1/rate-limited",
    f"/{ECONOMY}/v1/server-error",
)

ROUTING_RULES = (
    (f"{ECONOMY}{CURRENCY}", "rotator_only"),  # must never push the credential through the rotator
    (f"{ECONOMY}/v1/user/hop", "prefer_rotator"),
    (f"{ECONOMY}/v1/redirect-to-currency", "rotator_only"),
    ("games.roblox.com/v1/rotated", "rotator_only"),
)


def install_routes(run: AppRun) -> None:
    """The mock Roblox's answers, by path (module docstring)."""
    fixture = run.fixture()
    respond = fixture.MockResponse
    json_type = ("Content-Type", "application/json")

    def currency(record: Any) -> Any:
        robux = "secret" if record.header("Cookie") else "anonymous"
        return respond(body=json.dumps({"robux": robux}).encode())

    def hop(record: Any) -> Any:
        target = (
            "https://games.roblox.com/v1/games?via=credhop-games"
            if "to=games" in record.path
            else f"https://{ECONOMY}/v2/other?via=credhop"
        )
        return respond(status=302, body=b"", headers=[("Location", target), json_type])

    def to_currency(record: Any) -> Any:
        target = f"https://{ECONOMY}{CURRENCY}?via=anonredirect"
        return respond(status=302, body=b"", headers=[("Location", target), json_type])

    def relative(record: Any) -> Any:
        return respond(status=307, body=b"", headers=[("Location", f"{CURRENCY}?via=relredirect"), json_type])

    def csrf(record: Any) -> Any:
        if record.method != "GET" and not record.header("x-csrf-token"):
            return respond(
                status=403,
                body=b'{"errors":[{"code":0,"message":"Token Validation Failed"}]}',
                headers=[("x-csrf-token", "tok-confinement-probe"), json_type],
            )
        return respond(body=b'{"ok":true}')

    run.mock.routes.update(
        {
            CURRENCY: currency,
            CURRENCY + "/": currency,
            "/v1/user/hop": hop,
            "/v1/redirect-to-currency": to_currency,
            "/v1/relative-redirect": relative,
            "/v1/csrf": csrf,
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
                kwargs = {"content": b'{"a":1}', "headers": {"Content-Type": "application/json"}}
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


def cookie_problems(run: AppRun, allowed: set[tuple[str, str]]) -> list[str]:
    """Every mock request that carried the cookie where it must not (module docstring)."""
    problems: list[str] = []
    expected_cookie = f".ROBLOSECURITY={run.credential}"
    for record in run.cookie_requests():
        host = (record.header("X-Roxy-Test-Host") or record.header("Host") or "").lower()
        path, _, query = record.path.partition("?")
        label = f"{record.method} {host}{record.path[:80]}"
        if record.header("Cookie") != expected_cookie:
            problems.append(f"{label}: a cookie other than the slot value")
        if record.header("X-Exit-Ip"):
            problems.append(f"{label}: the cookie went through the rotator")
        if record.method != "GET":
            problems.append(f"{label}: the cookie on a {record.method}")
        # Rules match case-insensitively, as v1 did, and Roblox paths are case-insensitive: compare lowercased.
        if (host, path.lower()) not in allowed:
            problems.append(f"{label}: the cookie on a target that is not allowlisted")
        if "via=" in query:
            problems.append(f"{label}: the cookie followed a redirect")
    return problems


def proxy_problems(run: AppRun) -> list[str]:
    run.proxy.wait_settled()
    recorded = run.proxy.all_recorded()
    problems = [f"rotator bytes: {item}" for item in leak_scan(recorded, run.credential)]
    if b".roblosecurity" in recorded.lower():
        problems.append("rotator bytes: the cookie name")
    return problems


async def test_caller_traffic_never_carries_the_credential(
    env: Any, credentials_dir: Path, fake_secrets: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """C1, C2, D1 end to end: with the credential ACTIVE, no caller request of any verb, encoding, routing rule
    or fallback leaves with the cookie unless it is a GET to an allowlisted endpoint, and then only from the
    server IP; redirect hops never carry it; the rotator never sees it."""
    async with running_app(env, credentials_dir, fake_secrets, monkeypatch) as run:
        install_routes(run)
        await run.settings(fallback_on_429=1)
        for pattern, mode in ROUTING_RULES:
            await run.rule("rules_routing", {"pattern": pattern, "mode": mode})
        await run.activate_credential()
        probe_only = {("users.roblox.com", PROBE_PATH)}

        # Phase 1, D1 as shipped: the allowlist is empty, so nothing a caller does may carry the cookie.
        statuses = await battery(run)
        await stale_while_revalidate(run, "/games.roblox.com/v1/games?universeIds=5")
        await stale_while_revalidate(run, f"/{ECONOMY}{CURRENCY}?swr=1")
        assert cookie_problems(run, probe_only) == []
        assert [r for r in run.cookie_requests() if r.path.split("?")[0] != PROBE_PATH] == []
        assert proxy_problems(run) == []
        # The battery really exercised what it claims (otherwise the assertions above prove nothing).
        records = run.mock_requests()
        assert any("via=anonredirect" in r.path for r in records), "the anonymous redirect was not followed"
        assert any("via=relredirect" in r.path for r in records), "the relative redirect was not followed"
        assert any(r.header("x-csrf-token") for r in records), "no CSRF retry happened"
        assert any(r.header("X-Exit-Ip") for r in records), "nothing went through the rotator"
        assert statuses[("OPTIONS", 204)] == len(PATHS)
        assert {status for (method, status) in statuses if method == "GET"} >= {200, 404}

        # Phase 2: two allowlist rows. Only GET (and HEAD, which runs as GET) to those endpoints may use it.
        await run.ctx.upstream.reset_state()
        currency_id = await run.rule(
            "credential_allowlist", {"pattern": f"{ECONOMY}{CURRENCY}", "cache_private": False}
        )
        await run.rule("credential_allowlist", {"pattern": f"{ECONOMY}/v1/user/hop", "cache_private": True})
        run.clock.advance(4000)  # every phase 1 cache entry is past its stale window
        before = len(run.cookie_requests())
        await battery(run)
        await stale_while_revalidate(run, f"/{ECONOMY}{CURRENCY}?swr=2")
        allowed = probe_only | {(ECONOMY, CURRENCY), (ECONOMY, CURRENCY + "/"), (ECONOMY, "/v1/user/hop")}
        assert cookie_problems(run, allowed) == []
        assert proxy_problems(run) == []
        assert len(run.cookie_requests()) > before, "the allowlisted endpoint was never fetched with the credential"
        assert all(r.header("X-Exit-Ip") is None for r in run.cookie_requests())

        # Phase 3: `identical_anonymous` and a rejected credential: the anonymous answer may go through the rotator
        # (the routing rule says rotator_only), and it must still be anonymous.
        await run.ctx.upstream.reset_state()
        await run.rules().update("credential_allowlist", currency_id, {"identical_anonymous": True}, ADMIN, "probe")
        await run.ctx.egress.credential.mark_rejected("confinement probe")
        run.clock.advance(4000)
        before = len(run.cookie_requests())
        exits_before = sum(1 for r in run.mock_requests() if r.header("X-Exit-Ip"))
        for method in ("GET", "HEAD"):
            response = await run.request(method, f"/{ECONOMY}{CURRENCY}?phase=3")
            assert response.status_code == 200
        assert len(run.cookie_requests()) == before
        assert sum(1 for r in run.mock_requests() if r.header("X-Exit-Ip")) > exits_before
        assert proxy_problems(run) == []
        assert not run.ctx.egress.tripped(Egress.DIRECT)
        assert not run.ctx.egress.tripped(Egress.ROTATOR)


async def test_rotator_only_rules_everywhere_never_carry_the_cookie(
    env: Any, credentials_dir: Path, fake_secrets: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A routing rule for every host that forces the rotator, with direct switched off: the allowlisted endpoint
    still goes out only on the credential client (server IP), and every other request goes out anonymously."""
    async with running_app(env, credentials_dir, fake_secrets, monkeypatch) as run:
        install_routes(run)
        await run.activate_credential()
        await run.settings(direct_enabled=0)
        await run.rule("credential_allowlist", {"pattern": f"{ECONOMY}{CURRENCY}", "cache_private": True})
        for host in ("economy.roblox.com", "games.roblox.com", "users.roblox.com"):
            await run.rule("rules_routing", {"pattern": host, "mode": "rotator_only"})
        for path in (f"/{ECONOMY}{CURRENCY}", f"/{ECONOMY}/v1/redirect-to-currency", "/games.roblox.com/v1/x"):
            for method in ("GET", "HEAD", "POST"):
                kwargs: dict[str, Any] = {"content": b"{}"} if method == "POST" else {}
                await run.request(method, path, **kwargs)
        allowed = {("users.roblox.com", PROBE_PATH), (ECONOMY, CURRENCY)}
        assert cookie_problems(run, allowed) == []
        assert proxy_problems(run) == []
        cred = [r for r in run.cookie_requests() if r.path.startswith(CURRENCY)]
        assert len(cred) == 2  # GET and HEAD (cache_private: every caller request makes its own credential call)


@pytest.mark.xfail(
    strict=True,
    reason=(
        "F3: a credential_allowlist row inherits the shared glob matcher's implicit subpath rule "
        "(`^pattern(?:/.*)?$`), so a row for one endpoint also sends the credential to every endpoint below it"
    ),
)
async def test_allowlist_row_grants_only_its_endpoint(
    env: Any, credentials_dir: Path, fake_secrets: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Least privilege for D1 rows: allowlisting `economy.roblox.com/v1/user/currency` must not also hand the cookie
    to `/v1/user/currency/<anything>`, which Roblox serves as different endpoints."""
    async with running_app(env, credentials_dir, fake_secrets, monkeypatch) as run:
        install_routes(run)
        await run.activate_credential()
        await run.rule("credential_allowlist", {"pattern": f"{ECONOMY}{CURRENCY}", "cache_private": True})
        response = await run.get(f"/{ECONOMY}{CURRENCY}/history/transactions")
        assert response.status_code == 200
        leaked = [r.path for r in run.cookie_requests() if r.path.startswith(CURRENCY + "/history")]
        assert leaked == []


PROXY_VARIABLES = ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "http_proxy", "all_proxy")


async def test_environment_proxies_are_never_honored_by_the_app(
    env: Any, credentials_dir: Path, fake_secrets: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """C2 item 2 through the app: with every proxy variable pointing at a recording trap (and NO_PROXY empty), the
    credential probe, an allowlisted credential request and anonymous direct traffic never touch the trap."""
    fixture = AppRun.fixture()
    with fixture.MockUpstream() as trap_target, fixture.RecordingProxy(upstream=trap_target.address) as trap:
        for name in PROXY_VARIABLES:
            monkeypatch.setenv(name, trap.url)
        monkeypatch.setenv("NO_PROXY", "")
        monkeypatch.setenv("no_proxy", "")
        async with running_app(env, credentials_dir, fake_secrets, monkeypatch) as run:
            install_routes(run)
            await run.activate_credential()
            await run.rule("credential_allowlist", {"pattern": f"{ECONOMY}{CURRENCY}", "cache_private": True})
            for path in (f"/{ECONOMY}{CURRENCY}", "/games.roblox.com/v1/games?universeIds=1"):
                run.clock.advance(5)
                assert (await run.get(path)).status_code == 200
            assert any(r.path.startswith(CURRENCY) for r in run.cookie_requests())
        trap.wait_settled()
        assert trap.exchanges == []
        assert trap_target.requests == []


async def test_shared_state_unavailable_never_uses_the_credential(
    env: Any, credentials_dir: Path, fake_secrets: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """C7: when control.db cannot be read right before the cookie would be attached, the credential is not used,
    and the allowlisted endpoint is not sent anonymously instead (plan 6.9): the caller gets a 503."""
    from roxy.storage.db import SharedStateUnavailable

    async with running_app(env, credentials_dir, fake_secrets, monkeypatch) as run:
        install_routes(run)
        await run.activate_credential()
        await run.rule("credential_allowlist", {"pattern": f"{ECONOMY}{CURRENCY}", "cache_private": True})
        before = len(run.mock_requests())

        async def unavailable(*args: Any, **kwargs: Any) -> Any:
            raise SharedStateUnavailable("control", "probe: disk gone")

        monkeypatch.setattr(run.ctx.dbs.control, "read", unavailable)
        run.clock.advance(5)
        response = await run.get(f"/{ECONOMY}{CURRENCY}")
        assert response.status_code == 503
        assert response.headers["roxy-refusal"] == "credential_unavailable"  # refused at authorize, fail closed
        assert len(run.mock_requests()) == before  # neither with the cookie nor anonymously
