"""Public markers can never switch an egress off: probes for plan C2 item 5 and 19.5 item 2b.

What this is
    Probes that try to trip the leak guard (which disables the direct or rotator egress fleet-wide until an admin
    re-enables it) with text any anonymous caller can type: every 24+ character window of the public
    `TOKEN_PREFIX` warning, of `.ROBLOSECURITY=` followed by it, in every ASCII case, raw and percent-encoded, in
    the URL, a header and the body; through the guard's matcher, through the real egress clients, and through
    the whole app. Finding F1 (fixed): a credential stored with its cookie name in front
    (`.ROBLOSECURITY=_|WARNING...`, the form browser tools copy) used to make that public text "secret", so any
    caller could disable every egress. The probes below pin the fix: the pair is stored as the bare value, and the
    matcher ignores public text wherever it sits in whatever value was stored.

Why it exists
    The leak guard's trip is deliberately drastic (C2 item 4). That makes it a denial of service lever unless the
    matcher only ever matches text that is really secret. `LeakMatcher` used to strip the public prefix with
    `str.removeprefix(TOKEN_PREFIX)`, which worked only when the stored value started with exactly that text; it
    now removes every run of public text (`credential.secret_spans`).

How it works
    The egress-level probes build `EgressClients` over the test databases with the development override pointing
    at a loopback mock (nothing leaves the machine). The app-level probes use `confinement_harness.running_app`.
    A trip is detected by `CredentialLeakBlocked`, `egress.tripped(...)` and the guard counters. The matcher probes
    build `LeakMatcher` directly from odd stored shapes and check both directions: no public window matches, and
    every 24 character window of the real secret still does (so the probe is not vacuous).

What to read next
    `src/roxy/egress/credential.py` (`LeakMatcher`, `_validate_value`), `src/roxy/egress/guard.py`,
    `src/roxy/abuse/checks/auth_smuggling.py` (the ingress half), `tests/security/test_credential_suite.py`.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx
import pytest
from confinement_harness import ADMIN, load_fixture, running_app

from roxy.core.clock import SYSTEM_CLOCK
from roxy.core.reasons import Egress
from roxy.core.redact import ROBLOX_COOKIE_NAME, TOKEN_PREFIX, SecretRegistry
from roxy.egress.clients import EgressClients
from roxy.egress.credential import LeakMatcher
from roxy.egress.errors import AuthSmugglingBlocked
from roxy.egress.models import OutboundRequest

harness = load_fixture("recording_proxy")
TIMEOUT = httpx.Timeout(5.0)
COOKIE_PAIR = ROBLOX_COOKIE_NAME + "="
PUBLIC_TEXTS = (TOKEN_PREFIX, COOKIE_PAIR + TOKEN_PREFIX, "Cookie: " + COOKIE_PAIR + TOKEN_PREFIX)
FRAGMENT = "Sharing-this-will-allow-someone-to-log-in"
"""41 characters of the public warning: no full `TOKEN_PREFIX`, no `.ROBLOSECURITY=`, so ingress lets it pass."""


def public_windows() -> Iterator[str]:
    """Every window of 24, 25, 31 and 48 characters (and the whole text) of each public string."""
    seen: set[str] = set()
    for text in PUBLIC_TEXTS:
        for size in (24, 25, 31, 48, len(text)):
            for start in range(0, max(1, len(text) - size + 1)):
                window = text[start : start + size]
                if len(window) >= 24 and window not in seen:
                    seen.add(window)
                    yield window


def spellings(text: str) -> tuple[str, ...]:
    """The text as typed, in both ASCII cases, percent-encoded, and fully percent-encoded."""
    full = "".join(f"%{byte:02X}" for byte in text.encode())
    return (text, text.lower(), text.upper(), quote(text, safe=""), full)


def out(url: str, method: str = "GET", **kwargs: Any) -> OutboundRequest:
    return OutboundRequest(method, url, kwargs.pop("headers", {}), kwargs.pop("content", None), TIMEOUT, **kwargs)


@pytest.fixture(autouse=True)
def _clean_registry() -> Iterator[None]:
    SecretRegistry.clear()
    yield
    SecretRegistry.clear()


@pytest.fixture
def mock() -> Iterator[Any]:
    with harness.MockUpstream() as server:
        server.routes["/v1/users/authenticated"] = harness.MockResponse(body=b'{"id": 1}')
        yield server


@pytest.fixture
async def make_egress(env: Any, dbs: Any, mock: Any) -> AsyncIterator[Callable[..., Awaitable[EgressClients]]]:
    built: list[EgressClients] = []

    async def factory(**options: Any) -> EgressClients:
        clients = EgressClients(
            env=env,
            settings=options.pop("settings", harness.FakeSettings()),
            dbs=dbs,
            clock=SYSTEM_CLOCK,
            worker_id=f"markers-{len(built)}",
            environ={"ROXY_TEST_UPSTREAM_BASE": mock.base_url, **options.pop("environ", {})},
            **options,
        )
        built.append(clients)
        await clients.start()
        return clients

    yield factory
    for clients in built:
        await clients.aclose()


# ----------------------------------------------------------------------------------------- normal configuration


async def test_public_text_is_never_a_leak_for_the_matcher(make_egress: Any) -> None:
    """C2 item 5: no window of the public warning or of `.ROBLOSECURITY=<warning>`, in any spelling, matches."""
    egress = await make_egress()
    matcher = egress.credential.leak_matcher()
    assert matcher.active  # the fake credential (prefix plus a secret part) is loaded
    hits = [
        spelling
        for window in public_windows()
        for spelling in spellings(window)
        if matcher.matches(spelling.encode()) or matcher.matches(b"x=" + spelling.encode() + b"&y=1")
    ]
    assert hits == []


async def test_public_text_through_both_egresses_never_disables_them(make_egress: Any, mock: Any) -> None:
    """The same public text in the URL, a header and the body of real direct and rotator sends: at most an
    auth smuggling refusal (the full marker), never a leak trip, and both egresses stay enabled."""
    windows = [*[w for w in public_windows() if len(w) in (24, 31)][::7], FRAGMENT, TOKEN_PREFIX]
    with harness.RecordingProxy(upstream=mock.address) as proxy:
        egress = await make_egress(environ={"ROXY_TEST_ROTATOR_PROXY": proxy.url_with_auth("dpuser", "dppw1")})
        for kind in (Egress.DIRECT, Egress.ROTATOR):
            sent = refused = 0
            for window in windows:
                encoded = quote(window, safe="")
                for request in (
                    out(f"https://games.roblox.com/v1/games?note={encoded}"),
                    out("https://games.roblox.com/v1/x", "POST", content=json.dumps({"n": window}).encode()),
                    out(
                        "https://games.roblox.com/v1/x", "POST", content=b"{}", headers={"Content-Type": f"x/{encoded}"}
                    ),
                ):
                    try:
                        await egress.send(kind, request)
                        sent += 1
                    except AuthSmugglingBlocked:
                        refused += 1
            assert egress.guard_stats[kind].leak_trips == 0, kind
            assert egress.is_enabled(kind) == (True, ""), kind
            assert sent > 0, kind
            assert refused > 0, kind  # the full marker is still refused: the battery reached the marker check


async def test_public_fragments_from_a_caller_never_disable_an_egress(
    env: Any, credentials_dir: Path, fake_secrets: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Through the app: a caller puts 24+ character pieces of the public warning in the query, the body and the
    path. Ingress lets them through (they are not the full marker), the guard must not treat them as a leak."""
    async with running_app(env, credentials_dir, fake_secrets, monkeypatch) as run:
        await run.activate_credential()
        fragments = [FRAGMENT, TOKEN_PREFIX[2:40], TOKEN_PREFIX[40:-2], TOKEN_PREFIX.lower()[5:60]]
        for fragment in fragments:
            run.clock.advance(5)
            await run.get("/games.roblox.com/v1/games", params={"universeIds": "1", "note": fragment})
            run.clock.advance(5)
            await run.request("POST", "/games.roblox.com/v1/games/list", content=json.dumps({"n": fragment}).encode())
            run.clock.advance(5)
            await run.get(f"/games.roblox.com/v1/{quote(fragment, safe='')}")
        assert not run.ctx.egress.tripped(Egress.DIRECT)
        assert not run.ctx.egress.tripped(Egress.ROTATOR)
        assert run.ctx.egress.guard_stats[Egress.DIRECT].leak_trips == 0
        assert len(run.mock.requests) > len(fragments)  # the requests really went out


# ------------------------------------------------------------------------------------------- finding F1


async def test_pasted_cookie_pair_keeps_public_text_public(
    env: Any, credentials_dir: Path, fake_secrets: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The bootstrap file holds the cookie as browser tools copy it (`.ROBLOSECURITY=<value>`). Roxy uses the bare
    value (its fingerprint is the bare value's), and an anonymous caller who sends 41 characters of the public
    warning in a query string, twice, disables nothing."""
    bare = fake_secrets["roblox_credential"]
    pasted = COOKIE_PAIR + bare
    async with running_app(env, credentials_dir, fake_secrets, monkeypatch, credential_file_text=pasted) as run:
        credential = run.ctx.egress.credential
        assert credential.status().present
        assert credential.status().fingerprint == credential.fingerprint_of(bare)  # normalized, not refused
        statuses = []
        for _ in range(2):  # before the fix, the second request went to the rotator once direct was switched off
            run.clock.advance(5)
            response = await run.get("/games.roblox.com/v1/games", params={"universeIds": "1", "note": FRAGMENT})
            statuses.append(response.status_code)
        tripped = (run.ctx.egress.tripped(Egress.DIRECT), run.ctx.egress.tripped(Egress.ROTATOR))
        assert (tripped, statuses) == ((False, False), [200, 200])
        assert run.ctx.egress.guard_stats[Egress.DIRECT].leak_trips == 0
        # The probe (Roxy's own credential use) sends the cookie name exactly once, with the bare value.
        await run.activate_credential()
        assert {record.header("Cookie") for record in run.cookie_requests()} == {f"{COOKIE_PAIR}{bare}"}


async def test_ui_replace_with_cookie_pair_keeps_public_text_public(
    make_egress: Any, fake_secrets: dict[str, str]
) -> None:
    """The admin pastes the pair on the Credential page: it is stored as the bare value (the same fingerprint as
    pasting the bare value), and public text never matches, after the paste or after a second, bare paste."""
    egress = await make_egress()
    bare = fake_secrets["roblox_credential"]
    status = await egress.credential.replace(COOKIE_PAIR + bare, ADMIN, reason="pasted from the browser")
    assert status.fingerprint == egress.credential.fingerprint_of(bare)
    during = egress.credential.leak_matcher().matches(FRAGMENT.encode())
    await egress.credential.replace(bare, ADMIN, reason="pasted again")
    after = egress.credential.leak_matcher().matches(FRAGMENT.encode())
    assert (during, after) == (False, False)
    assert egress.credential.leak_matcher().matches(bare[-30:].encode())  # the secret itself is still watched


async def test_ui_replace_refuses_a_value_that_still_names_the_cookie(
    make_egress: Any, fake_secrets: dict[str, str]
) -> None:
    """Only one leading pair is removed: a doubled pair, or the name anywhere else, is refused (never stored)."""
    egress = await make_egress()
    bare = fake_secrets["roblox_credential"]
    before = egress.credential.status().fingerprint
    for bad in (COOKIE_PAIR + COOKIE_PAIR + bare, bare + ROBLOX_COOKIE_NAME, "Cookie:" + COOKIE_PAIR + bare):
        with pytest.raises(ValueError):
            await egress.credential.replace(bad, ADMIN, reason="probe")
    assert egress.credential.status().fingerprint == before


SECRET_PART = "FAKETESTSECRET" + "0123456789ABCDEF" * 12
"""A stand-in secret part (no run of 12 characters of it appears in the public warning)."""

ODD_SHAPES: dict[str, tuple[str, tuple[str, ...]]] = {
    # name: (the stored value, the secret pieces it holds)
    "bare": (TOKEN_PREFIX + SECRET_PART, (SECRET_PART,)),
    "pair": (COOKIE_PAIR + TOKEN_PREFIX + SECRET_PART, (SECRET_PART,)),
    "lowercase_pair": (COOKIE_PAIR.lower() + TOKEN_PREFIX + SECRET_PART, (SECRET_PART,)),
    "junk_before_prefix": ("x" + TOKEN_PREFIX + SECRET_PART, (SECRET_PART,)),
    "prefix_without_first_chars": (TOKEN_PREFIX[2:] + SECRET_PART, (SECRET_PART,)),
    "prefix_after_secret": (SECRET_PART + TOKEN_PREFIX, (SECRET_PART,)),
    "prefix_on_both_sides": (TOKEN_PREFIX + SECRET_PART + TOKEN_PREFIX, (SECRET_PART,)),
    "prefix_in_the_middle": (SECRET_PART[:60] + TOKEN_PREFIX + SECRET_PART[60:], (SECRET_PART[:60], SECRET_PART[60:])),
    "prefix_twice": (TOKEN_PREFIX + TOKEN_PREFIX + SECRET_PART, (SECRET_PART,)),
    "lowercase_prefix": (TOKEN_PREFIX.lower() + SECRET_PART, (SECRET_PART,)),
}


@pytest.mark.parametrize("shape", list(ODD_SHAPES), ids=list(ODD_SHAPES))
def test_matcher_ignores_public_text_wherever_it_is_stored(shape: str) -> None:
    """Whatever a stored value looks like (rotated cookies Roblox sends are not validated, and a matcher keeps old
    values), no window of the public text matches, while every 24 character window of each secret piece does."""
    value, pieces = ODD_SHAPES[shape]
    matcher = LeakMatcher((value,))
    hits = [
        spelling
        for window in public_windows()
        for spelling in spellings(window)
        if matcher.matches(spelling.encode()) or matcher.matches(b"x=" + spelling.encode() + b"&y=1")
    ]
    assert hits == []
    for piece in pieces:
        for size in (24, 31):
            for start in range(0, len(piece) - size + 1, 5):
                window = piece[start : start + size]
                assert matcher.matches(b"q=" + window.lower().encode()), (shape, start, size)
