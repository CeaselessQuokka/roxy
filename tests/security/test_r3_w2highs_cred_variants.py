"""Wave 2 high and credential fixes, new variants (review round 3, lens w2highs): cred-1 and cred-2.

What this is
    Adversarial variants of two review round fixes in `src/roxy/egress/credential.py`:
      * cred-1 (high): a stored or rotated credential must never arm the leak guard with public text. The fix stores
        the canonical (percent-decoded) value and watches only secret parts of 24 or more characters. The fix tests
        cover one spelling (`encodeURIComponent`) and one caller fragment (`_|WARNING:`). Here: double, triple and
        fourfold encoding, lowercase hex escapes, a fully %XX encoded warning, the encoded cookie pair, a lowercased
        or clipped warning, and other public fragments in plain, encoded and double encoded form, at the matcher and
        on the real app (bootstrap file, UI replace, and a rotated cookie in a quoted, mixed case Set-Cookie).
      * cred-2 (medium): an audit reason that repeats a credential must be redacted, so the value must be known to
        `SecretRegistry` before the audit row is written. The fix registers a replaced value first. Here: the other
        admin entry point that writes a reason next to a credential, `delete_ui_value` (going back to the bootstrap
        file), after the registry has seen several replaced values.

Why it exists
    `SecretRegistry` keeps at most `_MAX_VALUES_PER_NAME` (3) values per name, newest first. The bootstrap value used
    to share its name with every UI value, was registered once at start, and nothing registered it again: after three
    UI replaces in one worker's life the bootstrap value was pushed out, and going back to it (plan C1: the only way
    back is deleting the UI value) left the credential in use unknown to every redaction point: the audit reason, the
    log filter, the outcome records, captures and the LLM export (plan 9.15, C2 item 8). Finding W2H-1, fixed: the
    bootstrap value and the value in use now have registry names of their own (`BOOTSTRAP_SECRET_NAME`,
    `IN_USE_SECRET_NAME`); `tests/unit/egress/test_egress_secret_roles.py` covers every path (replace N times, refused
    pastes, revert, restart). The leak guard was never affected (`_rebuild_matcher` always includes the bootstrap).

How it works
    The matcher variants call `LeakMatcher` and `inspect_request` directly; the app variants use
    `confinement_harness.running_app` (the real app against a loopback mock) exactly as the cred-1 fix test does.
    The registry variant replaces the credential three times through the audited `replace`, deletes the UI value
    with a reason that repeats the bootstrap value's secret part (a paste into the wrong box, as in cred-2), then
    scans the stored reason with `leak_scan` and asks `redact_text` whether it still knows the credential in use.

What to read next
    `src/roxy/egress/credential.py` (`_resolve_slot`, `delete_ui_value`, `replace`), `src/roxy/core/redact.py`
    (`SecretRegistry.register`, `_MAX_VALUES_PER_NAME`), `tests/security/test_rr_cred_encoded_paste.py` and
    `tests/security/test_rr_cred_audit_reason.py` (the fix tests these extend).
"""

from __future__ import annotations

import re
import secrets
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx
import pytest
from confinement_harness import ADMIN, PROBE_PATH, leak_scan, running_app, secret_part

from roxy.core.reasons import Egress
from roxy.core.redact import TOKEN_PREFIX, redact_text
from roxy.egress.credential import LeakMatcher, _clean_value
from roxy.egress.guard import Verdict, inspect_request


def encode_uri_component(value: str) -> str:
    """What JavaScript's `encodeURIComponent` (and cookie tools built on it) makes of a cookie value."""
    return quote(value, safe="-_.!~*'()")


def lower_hex(encoded: str) -> str:
    """`encoded` with every %XX escape in lowercase hex (`%7c`), the letters of the text unchanged."""
    return re.sub(r"%[0-9A-F]{2}", lambda match: match.group(0).lower(), encoded)


def fully_encoded(value: str, *, lower: bool = False) -> str:
    """Every character as a %XX escape (upper or lower case hex)."""
    text = "".join(f"%{ord(ch):02X}" for ch in value)
    return text.lower() if lower else text


SECRET = "VARIANTSECRET" + "0123456789ABCDEF" * 6
VALUE = TOKEN_PREFIX + SECRET

STORED_SPELLINGS = {
    "encoded": encode_uri_component(VALUE),
    "encoded_lower_hex": encode_uri_component(TOKEN_PREFIX).lower() + SECRET,
    "encoded_twice": encode_uri_component(encode_uri_component(VALUE)),
    "encoded_three_times": encode_uri_component(encode_uri_component(encode_uri_component(VALUE))),
    "encoded_four_times": encode_uri_component(encode_uri_component(encode_uri_component(encode_uri_component(VALUE)))),
    "warning_fully_encoded": fully_encoded(TOKEN_PREFIX) + SECRET,
    "warning_fully_encoded_lower_twice": encode_uri_component(fully_encoded(TOKEN_PREFIX, lower=True)) + SECRET,
    "cookie_pair_encoded": encode_uri_component(".ROBLOSECURITY=" + VALUE),
    "mixed_escape_case": TOKEN_PREFIX.replace("|", "%7c", 1).replace(":", "%3A") + SECRET,
    "warning_lowercased": TOKEN_PREFIX.lower() + SECRET,
    "warning_without_first_character": TOKEN_PREFIX[1:] + SECRET,
    "warning_without_last_two": TOKEN_PREFIX[:-2] + SECRET,
    "secret_before_the_warning": SECRET + TOKEN_PREFIX,
}

PUBLIC_FRAGMENTS = (
    "_|WARNING:",
    "-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone",
    "Sharing-this-will-allow-someone-to-log-in-as-you-and-to-steal-your-ROBUX",
    "ROBUX-and-items.|_",
    TOKEN_PREFIX[1:-1],  # the whole warning minus one character at each end: not the full marker, so ingress passes
)


def caller_spellings(fragment: str) -> list[str]:
    """How a caller can send a public fragment: as is, lowercased, encoded once and twice (upper and lower hex)."""
    once = quote(fragment, safe="")
    return [fragment, fragment.lower(), once, once.lower(), quote(once, safe=""), fully_encoded(fragment, lower=True)]


@pytest.mark.parametrize("spelling", sorted(STORED_SPELLINGS))
def test_cred1_no_stored_spelling_turns_public_text_into_a_trip_wire(spelling: str) -> None:
    """cred-1 variant (holds): whatever spelling the admin pasted, the stored canonical value watches only the
    secret, never a public fragment in any spelling a caller can send, and the secret is still found."""
    stored = _clean_value(STORED_SPELLINGS[spelling]).text  # what `replace` and the bootstrap loader store
    matcher = LeakMatcher((stored,))
    tripped = []
    for fragment in PUBLIC_FRAGMENTS:
        for sent in caller_spellings(fragment):
            request = httpx.Request("GET", "https://games.roblox.com/v1/games", params={"universeIds": "1", "q": sent})
            if inspect_request(request, b"", matcher, 1 << 20).verdict is Verdict.LEAK:
                tripped.append(sent[:40])
    assert tripped == []
    assert matcher.matches(SECRET[13:43].encode())  # not vacuous: the real secret is still watched


@pytest.mark.parametrize(
    "source", ["bootstrap_encoded_twice", "ui_cookie_pair_lower_hex", "rotated_quoted_mixed_case_encoded_twice"]
)
async def test_cred1_variant_pastes_never_let_a_caller_disable_an_egress(
    source: str, env: Any, credentials_dir: Path, fake_secrets: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """cred-1 variant on the real app (holds): other spellings of the paste, and a rotated cookie that Roblox sends
    quoted, with a mixed case cookie name and encoded twice; callers then send several public fragments in several
    spellings. Every answer is 200 and no egress is tripped."""
    credential = fake_secrets["roblox_credential"]
    file_text = encode_uri_component(encode_uri_component(credential)) if source == "bootstrap_encoded_twice" else None
    async with running_app(env, credentials_dir, fake_secrets, monkeypatch, credential_file_text=file_text) as run:
        if source == "ui_cookie_pair_lower_hex":
            pasted = lower_hex(quote(".ROBLOSECURITY=" + credential, safe=""))  # the cookie pair, %7c style escapes
            await run.ctx.egress.credential.replace(pasted, ADMIN, reason="pasted from a cookie tool")
        await run.activate_credential()
        assert run.ctx.egress.credential.status().fingerprint == run.ctx.egress.credential.fingerprint_of(credential)
        if source == "rotated_quoted_mixed_case_encoded_twice":
            rotated = encode_uri_component(encode_uri_component(TOKEN_PREFIX + "REFRESHEDBYROBLOX" + "5A" * 120))
            run.mock.routes[PROBE_PATH] = run.fixture().MockResponse(
                body=b'{"id": 1, "name": "owner"}',
                headers=[
                    ("Content-Type", "application/json"),
                    ("Set-Cookie", f'.robloSECURITY="{rotated}"; domain=.roblox.com; path=/; secure; HttpOnly'),
                ],
            )
            run.clock.advance(5)
            probe = await run.ctx.egress.credential.probe("liveness", fetch=run.ctx.upstream.credential_probe_fetch)
            assert probe.ok, probe
        statuses = []
        for fragment in PUBLIC_FRAGMENTS:
            for sent in caller_spellings(fragment)[::2]:  # as is, encoded once, encoded twice
                run.clock.advance(5)
                response = await run.get("/games.roblox.com/v1/games", params={"universeIds": "1", "note": sent})
                statuses.append(response.status_code)
        tripped = (run.ctx.egress.tripped(Egress.DIRECT), run.ctx.egress.tripped(Egress.ROTATOR))
        trips = run.ctx.egress.guard_stats[Egress.DIRECT].leak_trips
        assert (tripped, trips, set(statuses)) == ((False, False), 0, {200})


async def test_cred2_going_back_to_the_bootstrap_value_keeps_it_redacted(
    env: Any, credentials_dir: Path, fake_secrets: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """cred-2 variant (finding W2H-1, fixed): the reason of `delete_ui_value` repeats the bootstrap value (a paste
    into the wrong box), after four replaces in this worker (for example four paste attempts, one more than the
    registry keeps per name). The credential in use must stay known to the redaction layer, and the audit row must
    not hold it."""
    bootstrap = fake_secrets["roblox_credential"]
    bare = secret_part(bootstrap)  # copied without the public warning, so no shape rule can find it
    async with running_app(env, credentials_dir, fake_secrets, monkeypatch) as run:
        manager = run.ctx.egress.credential
        assert redact_text(f"x {bare} y") == "x [redacted] y"  # control: known while the worker is fresh
        for attempt in range(4):
            pasted = f"PASTEATTEMPT{attempt}" + secrets.token_hex(64).upper()
            await manager.replace(pasted, ADMIN, reason=f"paste attempt {attempt}")
        await manager.delete_ui_value(ADMIN, reason=f"back to the file cookie {bare}")
        assert manager.status().source == "bootstrap"  # the bootstrap value is the credential now
        rows = run.ctx.dbs.control.read_sync(
            lambda conn: conn.execute(
                "SELECT reason FROM audit_log WHERE action = 'credential.delete_ui_value'"
            ).fetchall()
        )
        reasons = [str(row[0] or "") for row in rows]
        assert len(reasons) == 1  # the row was really written
        still_known = redact_text(f"x {bare} y") == "x [redacted] y"
    assert {"audit reason": leak_scan(reasons[0], bootstrap), "redaction knows it": still_known} == {
        "audit reason": [],
        "redaction knows it": True,
    }
