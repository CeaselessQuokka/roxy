"""A percent-encoded credential paste turns public text into a leak-guard trip wire (review lens cred, finding cred-1).

What this is
    Adversarial probes for plan C2 item 5 ("public markers are not leak trips... this stops an attacker from
    switching the rotator off on demand") and 19.5 item 2b, against the fix of finding F1. The credential is stored
    in the form JavaScript's `encodeURIComponent` and many cookie tools produce: the public warning with `|` and `:`
    percent-encoded (`_%7CWARNING%3A-DO-NOT-SHARE-THIS...%7C_<secret>`). `_clean_value` accepts it (it only refuses
    the cookie name, control characters and `;,"\\`), and Roblox's ASP.NET front end unescapes cookie values, so it
    is a working credential. An anonymous caller then sends the ten characters `_|WARNING:` in a query value.

Why it exists
    `secret_spans` drops runs of 12 or more characters that the raw public texts contain, but the encoded head of the
    warning (`_%7cwarning%3a`, 14 characters) is not raw public text, so it survives as a short "secret part", and
    `LeakMatcher` watches parts of 8 to 23 characters WHOLE. The upstream URL re-encodes the caller's `_|WARNING:` to
    exactly `_%7CWARNING%3A`, the guard reports a leak, and the direct egress is switched off fleet-wide (then the
    rotator, on the next request). Ingress does not refuse the caller: ten characters are not the full marker.

How it works
    `confinement_harness.running_app` runs the real app against a loopback mock. The encoded value is stored as the
    bootstrap file, through the audited `replace`, or (no admin action) arrives as a refreshed cookie in a
    `Set-Cookie` on Roxy's own probe, which `observe_set_cookie` adds to the matcher; Roxy's probe makes the
    credential `active`, and then two caller GETs carry the public fragment. Correct behavior: both are answered 200
    and no egress is tripped. Fixed in the review round: `_clean_value` and `observe_set_cookie` store the canonical
    (percent-decoded) value, and the matcher classifies public text in that form and never watches a short leftover
    whole, so encoded public text is public text.

What to read next
    `src/roxy/egress/credential.py` (`_clean_value`, `secret_spans`, `LeakMatcher._watch`), `src/roxy/egress/guard.py`
    and `tests/security/test_confinement_markers.py` (the F1 probes this one extends).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx
import pytest
from confinement_harness import ADMIN, PROBE_PATH, running_app

from roxy.core.reasons import Egress
from roxy.core.redact import TOKEN_PREFIX
from roxy.egress.credential import LeakMatcher
from roxy.egress.guard import Verdict, inspect_request

PUBLIC_FRAGMENT = "_|WARNING:"
"""Ten characters of the public warning: not the full `TOKEN_PREFIX`, so the ingress auth smuggling check passes."""


def encode_uri_component(value: str) -> str:
    """What JavaScript's `encodeURIComponent` (and cookie tools built on it) makes of a cookie value."""
    return quote(value, safe="-_.!~*'()")


def test_the_encoded_head_of_the_warning_is_public_text() -> None:
    """The mechanism, at the matcher (fixed): the value is classified in its canonical, percent-decoded form, so
    the encoded head `_%7cwarning%3a` is public text and never a "secret part", in any spelling a caller can
    produce; the real secret is still watched, raw and encoded."""
    secret = "ENCODEDPASTE" + "0123456789ABCDEF" * 8
    value = encode_uri_component(TOKEN_PREFIX) + secret
    matcher = LeakMatcher((value,))
    for spelling in (PUBLIC_FRAGMENT, quote(PUBLIC_FRAGMENT), quote(PUBLIC_FRAGMENT, safe=""), "_%7cwarning%3a"):
        assert not matcher.matches(b"https://games.roblox.com/v1/games?note=" + spelling.encode()), spelling
    assert not matcher.matches(encode_uri_component(TOKEN_PREFIX).encode())  # the whole encoded warning too
    assert matcher.matches(b"q=" + secret[5:35].encode())
    # Encoded by a caller, the secret is still found: the guard decodes every part before matching.
    full = "".join(f"%{ord(ch):02X}" for ch in secret[5:35])
    request = httpx.Request("GET", f"https://games.roblox.com/v1/games?q={full}")
    assert inspect_request(request, b"", matcher, 1024).verdict is Verdict.LEAK


@pytest.mark.parametrize("source", ["bootstrap_file", "ui_replace", "rotated_on_the_probe"])
async def test_encoded_credential_paste_never_lets_a_caller_disable_an_egress(
    source: str, env: Any, credentials_dir: Path, fake_secrets: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """`rotated_on_the_probe`: no admin action at all. Roblox answers Roxy's own probe (the one credential use under
    D1) with a refreshed cookie in the encoded form ASP.NET's cookie API writes; `observe_set_cookie` adds it to the
    matcher unvalidated, which arms the same trip wire."""
    encoded = encode_uri_component(fake_secrets["roblox_credential"])
    assert encoded != fake_secrets["roblox_credential"]  # the paste really is the encoded form
    file_text = encoded if source == "bootstrap_file" else None
    async with running_app(env, credentials_dir, fake_secrets, monkeypatch, credential_file_text=file_text) as run:
        if source == "ui_replace":
            await run.ctx.egress.credential.replace(encoded, ADMIN, reason="pasted from a cookie tool")
        await run.activate_credential()  # Roxy's own probe: the value is accepted and becomes active
        credential = run.ctx.egress.credential
        assert credential.status().present
        # Stored, fingerprinted and sent in its canonical form, the one Roblox issues (finding cred-1).
        assert credential.status().fingerprint == credential.fingerprint_of(fake_secrets["roblox_credential"])
        cookies = {record.header("Cookie") for record in run.cookie_requests()}
        assert cookies == {f".ROBLOSECURITY={fake_secrets['roblox_credential']}"}
        if source == "rotated_on_the_probe":
            rotated = encode_uri_component(TOKEN_PREFIX + "REFRESHEDBYROBLOX" + "5A" * 120)
            run.mock.routes[PROBE_PATH] = run.fixture().MockResponse(
                body=b'{"id": 1, "name": "owner"}',
                headers=[
                    ("Content-Type", "application/json"),
                    ("Set-Cookie", f".ROBLOSECURITY={rotated}; domain=.roblox.com; path=/; secure; HttpOnly"),
                ],
            )
            run.clock.advance(5)
            probe = await run.ctx.egress.credential.probe("liveness", fetch=run.ctx.upstream.credential_probe_fetch)
            assert probe.ok, probe
        statuses = []
        for _ in range(2):  # the second request would go to the rotator once direct is switched off
            run.clock.advance(5)
            response = await run.get("/games.roblox.com/v1/games", params={"universeIds": "1", "note": PUBLIC_FRAGMENT})
            statuses.append(response.status_code)
        tripped = (run.ctx.egress.tripped(Egress.DIRECT), run.ctx.egress.tripped(Egress.ROTATOR))
        trips = run.ctx.egress.guard_stats[Egress.DIRECT].leak_trips
        assert (tripped, trips, statuses) == ((False, False), 0, [200, 200])
