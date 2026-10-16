"""A credential piece a caller sends on the credential path is stored in cache.db key text (review lens cred,
finding cred-5).

What this is
    A variant of finding F4 ("credential piece in labels", fixed by scrubbing every caller-supplied label with
    `redact_label`). The F4 probe's injections all go out on an anonymous egress, where the leak guard refuses
    them before anything is fetched, so nothing is ever cached. The credential client has no guard (by design: it
    carries the cookie), so the same injection on an ALLOW_TOKEN endpoint whose grant is shared (`cache_private`
    off, as every shipped row is) was fetched, and its cache key (`GET games.roblox.com/v1/games?k=<piece> @cred`)
    was written to cache.db's `entries.key` column verbatim: key text is never scrubbed.

Why it exists
    Plan 9.15 and 19.7 ("inject secrets into requests and assert logs, captures, exports are clean"), and the F4 probe
    itself, require every database byte to be free of the credential. cache.db rows are shown by the cache browser
    (`CacheService.list_entries`, `get_entry`) and copied by backups. The same request also sends the piece to
    Roblox next to the cookie, where the anonymous path would have refused it as a leak.

How it works
    `confinement_harness.running_app` runs the real app; the credential is activated by Roxy's own probe, and the
    shipped endpoint policy grants it to `games GET /v1/games` (D1 revised). The caller sends a 40 character run of the
    credential's secret part as a query value, the cache settles (answers come before the cache.db write), and every
    SQLite file is scanned with `leak_scan`. Fixed in the review round: the credential path refuses the piece before the
    cookie is attached; the control request shows the endpoint is otherwise fetched with the cookie and stored. The
    piece request is not sent anonymously either (this endpoint may fall back to anonymous when the account is busy,
    never when the request itself is refused).

What to read next
    `src/roxy/cache/keys.py` (`build_key`), `src/roxy/cache/service.py` (`_absorb`, `_finish`),
    `src/roxy/egress/clients.py` (`_send_with`: no guard on the credential client), and
    `tests/security/test_confinement_records.py::test_injected_credential_piece_is_scrubbed_everywhere`.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from confinement_harness import leak_scan, running_app, secret_part

from roxy.core.reasons import Egress
from roxy.core.redact import TOKEN_PREFIX

GAMES = "games.roblox.com"
ENDPOINT = "/v1/games"


async def test_credential_piece_on_the_credential_path_never_reaches_cache_db(
    env: Any, credentials_dir: Path, fake_secrets: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fixed in the review round: `CredentialManager.authorize` runs the leak guard's inspection before the cookie
    is attached, so the request carrying the piece is refused as auth smuggling (400): nothing goes to Roblox,
    with the cookie or without, nothing is cached, and no egress is tripped. A clean request to the same endpoint
    is still fetched with the cookie and stored, so the probe is not vacuous."""
    piece = secret_part(fake_secrets["roblox_credential"])[30:70]
    async with running_app(env, credentials_dir, fake_secrets, monkeypatch) as run:
        await run.activate_credential()
        run.clock.advance(5)
        refused = await run.get(f"/{GAMES}{ENDPOINT}", params={"k": piece})
        run.clock.advance(5)
        control = await run.get(f"/{GAMES}{ENDPOINT}", params={"k": "plain"})
        await run.ctx.cache.settle()
        assert (refused.status_code, refused.headers.get("Roxy-Refusal")) == (400, "auth_smuggling")
        sent = [r.path for r in run.cookie_requests() if r.path.startswith(ENDPOINT)]
        assert sent == [f"{ENDPOINT}?k=plain"]  # only the clean request went out with the cookie
        reached = [r.path for r in run.mock_requests() if r.path.startswith(ENDPOINT)]
        assert reached == [f"{ENDPOINT}?k=plain"]  # and the piece went nowhere, not even anonymously
        assert not run.ctx.egress.tripped(Egress.DIRECT)
        assert not run.ctx.egress.tripped(Egress.ROTATOR)
        assert control.status_code == 200
        rows = run.ctx.dbs.cache.read_sync(lambda conn: conn.execute("SELECT count(*) FROM entries").fetchone()[0])
        assert rows >= 1  # the clean answer was stored
    cache_bytes = b"".join(
        path.read_bytes() for path in sorted(env.state_dir.iterdir()) if path.name.startswith("cache.db")
    )
    assert leak_scan(cache_bytes, TOKEN_PREFIX + piece) == []
