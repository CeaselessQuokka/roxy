"""Final review, constraints lens: the hard constraints C1, C2, C4, C6, C7 and owner decision D1, by attack.

What this is
    The reproductions of the findings of the constraints lens (`.remake/final_review/find_constraints.md`). Each
    was a strict xfail until the final review fixed its finding; each is a regression test now.

Why it exists
    The last review before v2 goes live. These are the places where the one Roblox credential can be used for an
    account nobody confirmed (C1), stays in use after Roxy learned it is dead or belongs to another account while
    control.db cannot record that (C7), reaches every caller after a paste into the wrong box (C4), or where a file
    has no bound (C6).

How it works
    Credential tests drive `roxy.egress.credential.CredentialManager` over the root conftest's migrated temporary
    databases and fake credentials, two managers standing in for two workers (or two colors); probes use a fake
    fetch that returns a chosen answer, so nothing leaves the machine. The paste test runs the real app through the
    admin API fixtures of `tests/integration/admin_api/conftest.py` (a signed-in admin, respx playing Roblox).
    `read_only` makes a database's writer refuse every write, as `tests/integration/test_review_c7_failure_modes.py`
    does.

What to read next
    `src/roxy/egress/credential.py` (`probe`, `_interpret_probe`, `_set_status`), `src/roxy/config/settings_service.py`,
    `src/roxy/abuse/pause.py`, `src/roxy/storage/migrate.py` (`recover_cache_db`).
"""

from __future__ import annotations

import types
from pathlib import Path
from typing import Any

import httpx
import pytest

from integration.admin_api.conftest import (  # noqa: F401 (the admin API fixtures, used by name)
    ApiApp,
    ApiSession,
    api,
    api_admin,
    api_app,
)
from roxy.config.audit import Actor
from roxy.core.clock import SYSTEM_CLOCK
from roxy.core.reasons import Egress
from roxy.core.redact import TOKEN_PREFIX, SecretRegistry
from roxy.egress.credential import CredentialManager
from roxy.egress.crypto import load_encryption_key
from roxy.egress.errors import CredentialUnavailable
from roxy.egress.events import EventSink
from roxy.egress.models import EgressResponse

ADMIN = Actor("admin", "owner", "127.0.0.1")
OTHER_ACCOUNT_VALUE = TOKEN_PREFIX + "OTHERACCOUNTCOOKIE" + "C3" * 80
PROBE_URL = "https://users.roblox.com/v1/users/authenticated"


class Settings:
    """Catalog defaults with the `RuntimeSettings` read API the credential manager uses."""

    def __init__(self, **overrides: Any) -> None:
        from roxy.config.catalog import defaults

        self._values = defaults()
        self._values.update(overrides)

    def get(self, key: str) -> Any:
        return self._values[key]


def make_manager(env: Any, dbs: Any, *, worker: str, credentials_dir: Path | None = None) -> CredentialManager:
    """One worker's credential manager over the shared test databases."""
    return CredentialManager(
        credentials_dir=credentials_dir or env.credentials_dir,
        dbs=dbs,
        settings=Settings(),
        clock=SYSTEM_CLOCK,
        worker_id=worker,
        encryption_key=load_encryption_key(env.credentials_dir),
        events=EventSink(lambda: None, lambda: None),
    )


def answer(status: int, body: bytes = b"") -> EgressResponse:
    """What Roblox answered to a probe."""
    return EgressResponse(
        status=status,
        headers=httpx.Headers({}),
        body=body,
        elapsed_ms=1.0,
        bytes_out=0,
        bytes_in=0,
        egress=Egress.CREDENTIAL,
        session_id=None,
        http_version="HTTP/1.1",
    )


def fetch_of(*answers: EgressResponse) -> Any:
    """A probe fetch that hands out `answers` in order (no network)."""
    queue = list(answers)

    async def fetch(url: str) -> EgressResponse:
        return queue.pop(0)

    return fetch


def read_only(db: Any, on: bool) -> None:
    """Make `db`'s writer connection refuse every write (SQLITE_READONLY, as a read-only file or full disk does)."""
    writer = next(thread for thread in db._threads if thread.role == "writer")
    writer._conn.execute(f"PRAGMA query_only={1 if on else 0}")


async def cookie_is_attached(manager: CredentialManager) -> bool:
    """Whether the manager would put the credential on an ordinary (allowlisted) request right now."""
    request = httpx.Request("GET", PROBE_URL)
    try:
        await manager.authorize(request, logical_url=request.url, probe=False)
    except CredentialUnavailable:
        return False
    return "cookie" in request.headers


@pytest.fixture(autouse=True)
def _clean_registry() -> Any:
    SecretRegistry.clear()
    yield
    SecretRegistry.clear()


# ---------------------------------------------------------------------------------------------- constraints-1 (C4)


async def test_constraints_1_pasted_credential_never_reaches_callers_or_settings_exports(
    api: ApiSession,  # noqa: F811 (the fixture imported above)
    api_app: ApiApp,  # noqa: F811
    fake_secrets: dict[str, str],
) -> None:
    """The owner pastes the cookie into the wrong box: the default downtime message (a setting) and the pause
    message. Roxy already treats the value as a secret (the audit row of the same change is redacted), but the
    pause answer every caller gets, the settings export and the settings history export carry it as typed.
    Either refusing the text or redacting it where it leaves fixes this; no 24 character run may leave."""
    piece = fake_secrets["roblox_credential"][-40:]
    run = piece[-24:]
    await api.patch(
        "settings",
        json={"changes": {"pause_message_default": "Back soon " + piece}, "reason": "pasted in the wrong box"},
    )
    await api.post("protection/pause", json={"paused": True, "message": "Maintenance " + piece})
    exported = await api.get("settings/export")
    history = await api.get("settings/history", params={"format": "json"})
    api_app.roblox.route(host="games.roblox.com").mock(return_value=httpx.Response(200, json={"data": []}))
    transport = httpx.ASGITransport(app=api_app.app, client=("127.0.0.1", 50001))
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as caller:
        answered = await caller.get(
            "/games.roblox.com/v1/games?universeIds=1",
            headers={"X-Forwarded-For": "203.0.113.9", "User-Agent": "Roblox/Linux"},
        )
    audit = await api.get("audit", params={"format": "json"})
    assert run not in audit.text  # the audit log already redacts it: Roxy knows the value is a secret
    leaks = {
        "caller answer": run in answered.text,
        "settings export": run in exported.text,
        "settings history export": run in history.text,
    }
    assert not any(leaks.values()), leaks


# ---------------------------------------------------------------------------------------------- constraints-2 (C1)


async def test_constraints_2_probe_of_the_old_value_never_confirms_the_replacement(env: Any, dbs: Any) -> None:
    """Worker w2's liveness probe (the old value, account 1) is on the wire when the admin replaces the credential
    in worker w1. The replacement has never been probed and its account is unknown, yet the old value's answer
    marks it active with account 1's fingerprint: allowlisted traffic uses it at once, and the C1 account check
    of the new value is skipped. The same happens to the other color's bootstrap value during a deploy after the
    owner changed the bootstrap file (the old color's probe confirms the new color's cookie), and after
    `delete_ui_value` while another worker's probe of the UI value is in flight."""
    w1 = make_manager(env, dbs, worker="w1")
    w2 = make_manager(env, dbs, worker="w2")
    await w1.start()
    await w2.start()
    first = await w1.probe("admin_check", fetch=fetch_of(answer(200, b'{"id": 1}')))
    assert first.outcome == "ok"

    async def replaced_while_on_the_wire(url: str) -> EgressResponse:
        await w1.replace(OTHER_ACCOUNT_VALUE, ADMIN, reason="a cookie of the new account")
        return answer(200, b'{"id": 1}')

    landed = await w2.probe("liveness", fetch=replaced_while_on_the_wire)
    assert landed.outcome == "ok"  # the old value is fine; that says nothing about the new one
    await w1.refresh(force=True)
    status = w1.status()
    assert status.fingerprint == w1.fingerprint_of(OTHER_ACCOUNT_VALUE)
    assert status.status != "active", "the replacement was marked active by the old value's probe"
    assert status.account_id_fingerprint is None, "the replacement carries the old value's account"
    assert not await cookie_is_attached(w1)


# ---------------------------------------------------------------------------------------------- constraints-3 (C7)


@pytest.mark.parametrize(
    ("kind", "verdict", "outcome"),
    [
        ("confirm_401", answer(401), "rejected"),
        ("admin_check", answer(200, b'{"id": 2}'), "account_mismatch"),
    ],
    ids=["confirmed_401", "account_mismatch"],
)
async def test_constraints_3_unrecorded_rejection_still_stops_the_credential(
    env: Any, dbs: Any, kind: str, verdict: EgressResponse, outcome: str
) -> None:
    """C7: when shared state cannot be written the credential is not used. A cooldown hot.db cannot take is kept in
    memory and honored (`_pending_cooldown`); a rejection (a 401 confirmed by the probe) or an account mismatch that
    control.db cannot take is only logged (`credential_status_not_saved`): the status stays active and the next
    allowlisted request carries the dead (or other account's) cookie, again and again, until a write succeeds."""
    manager = make_manager(env, dbs, worker="w1")
    await manager.start()
    assert (await manager.probe("admin_check", fetch=fetch_of(answer(200, b'{"id": 1}')))).outcome == "ok"
    read_only(dbs.control, True)
    try:
        result = await manager.probe(kind, fetch=fetch_of(verdict))
        assert result.outcome == outcome
        assert not manager.available(), f"the credential is still in use after {outcome}"
        assert not await cookie_is_attached(manager)
    finally:
        read_only(dbs.control, False)


# ---------------------------------------------------------------------------------------------- constraints-4 (C1)


async def test_constraints_4_answer_without_an_account_id_never_clears_a_mismatch(env: Any, dbs: Any) -> None:
    """After a probe saw another account (status rejected, `confirm-account` with the typed C1 warning required),
    any probe that is answered 200 with a body that holds no account id (an HTML challenge or error page Roblox
    sends with 200, `upstream/pages.py classify_page`, or a non-default `credential_probe_url`) is taken as
    `ok_no_account_id`: the status becomes active and the cookie of the other account is used, unconfirmed. The
    health check's probe (kind `health`, also on the scheduled runs) and the 401 confirmation probe both run while
    the credential is rejected, so this needs no admin action at all."""
    manager = make_manager(env, dbs, worker="w1")
    await manager.start()
    assert (await manager.probe("admin_check", fetch=fetch_of(answer(200, b'{"id": 1}')))).outcome == "ok"
    mismatch = await manager.probe("admin_check", fetch=fetch_of(answer(200, b'{"id": 2}')))
    assert mismatch.outcome == "account_mismatch"
    assert manager.status().status == "rejected"
    page = await manager.probe("health", fetch=fetch_of(answer(200, b"<html><body>Just a moment</body></html>")))
    assert page.outcome == "ok_no_account_id"
    assert manager.status().status != "active", "an answer that names no account confirmed an account switch"
    assert not await cookie_is_attached(manager)


# ---------------------------------------------------------------------------------------------- constraints-5 (C6)


# Fixed (fixer data): `migrate.recover_cache_db` keeps only the newest damaged copy, and `disk_history.measure_files`
# counts it.
def test_constraints_5_damaged_cache_copies_are_bounded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Plan P9 and C6: every file is bounded. `recover_cache_db` moves a damaged cache.db (and its WAL) to
    `cache.db.corrupt-<unix time>` on each start that finds one; nothing ever deletes those copies (the file prune
    job covers `exports/` and `snapshots/` only, and `disk_history.measure_files` and `/health DataBytes` count the
    four databases, so the disk budget and its alert never see them). Each copy can be as large as the cache tier.
    A bounded fix keeps at most one damaged copy (or none)."""
    from roxy.storage import migrate

    cache = tmp_path / "cache.db"
    for hour in range(3):
        cache.write_bytes(b"this is not an SQLite database " * 4096)
        stamp = 1_800_000_000 + hour * 3600
        monkeypatch.setattr(migrate, "time", types.SimpleNamespace(time=lambda stamp=stamp: stamp))
        assert migrate.recover_cache_db(cache) is not None
    kept = sorted(path.name for path in tmp_path.glob("cache.db.corrupt-*"))
    assert len(kept) <= 1, kept


# ---------------------------------------------------------------------------------------------- constraints-6 (C6)


async def test_constraints_6_the_account_burst_holds_across_traffic_and_probes(dbs: Any) -> None:
    """`credential_bucket_burst` (3) is "how many credential requests may go out back to back"; the reserved probe
    sub-bucket is carved out of the account's rate (18 + 2 per minute) but not out of its burst: allowlisted traffic
    keeps the whole burst of 3 in `egress:credential` and probes get `min(burst, reserved)` = 2 more in
    `egress:credential:probe`, so 5 account calls leave in the same instant (plan 7.3: the probe share is "of" the
    account's bucket). Back-to-back account calls are the shape Roblox's limiters punish most (the setting's own
    warning)."""
    from roxy.upstream import buckets

    settings = Settings()
    defaults = buckets.BucketDefaults.from_settings(settings)
    now = 1_800_000_000_000
    allowlisted = buckets.specs_for(Egress.CREDENTIAL, "economy.roblox.com", "economy.roblox.com/v1/a", defaults, None)
    probe = buckets.specs_for(
        Egress.CREDENTIAL,
        "users.roblox.com",
        "users.roblox.com/v1/users/authenticated",
        defaults,
        None,
        credential_probe=True,
    )
    at_once = 0
    for specs in (allowlisted,) * 4 + (probe,) * 3:  # more of each than any burst allows
        outcome = await buckets.reserve(dbs.hot, specs, now_ms=lambda: now, max_wait_ms=0)
        at_once += int(outcome.granted)
    assert at_once <= int(settings.get("credential_bucket_burst")), at_once
