"""The final review's egress fixes: probe verdicts, unsaved rejections, accounts after a replace, alert links, the
rotator's failure streak and its billing count.

What this is
    Unit tests for the fixes of findings constraints-2, constraints-3, constraints-4, docs_a-1, docs_a-2, brain-6,
    docs_a-10 and data-4 (`.remake/final_review/fix_egress.md`), next to the module tests they extend. The findings'
    own reproductions stay in `tests/review_final/` as regression tests; these pin the edges around them.

Why it exists
    Plan C1 (one account, never switched without a confirmation), C7 (the credential is not used when shared state
    cannot record what Roxy learned), plan 17.7 (every alert links its page and runbook) and plan 8.4 (the rotator's
    hard stop holds for the whole billing cycle).

How it works
    Real temporary control.db, hot.db and metrics.db from the root conftest; managers and pools stand in for workers
    (two of them for two workers or two colors); probes use a fake fetch, alerts a recording notifier, and the
    `read_only` helper makes a database's writer refuse writes the way a read-only file or a full disk does
    (as `tests/integration/test_review_c7_failure_modes.py` does). No network.

What to read next
    `src/roxy/egress/credential.py` (`_record_verdict`, `_named_answer`, `_unnamed_answer`), `src/roxy/egress/events.py`
    and `src/roxy/egress/rotator.py` (`record_result`, `BillingCount`).
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import httpx
import pytest

from roxy.config.audit import Actor
from roxy.core.clock import FakeClock
from roxy.core.reasons import Egress
from roxy.core.redact import TOKEN_PREFIX
from roxy.egress.accounting import EgressUsage
from roxy.egress.credential import ACCOUNT_CHANGED, ACCOUNT_MISMATCH, CredentialManager
from roxy.egress.crypto import load_encryption_key
from roxy.egress.errors import CredentialUnavailable
from roxy.egress.events import EgressAlert, EventSink, page_link, runbook_for
from roxy.egress.models import EgressResponse
from roxy.egress.rotator import (
    BILLING_KEY,
    STREAK_KEY,
    BillingCount,
    RotatorPool,
    billed_bytes,
    cycle_start_for,
    day_start_for,
    read_billing,
)
from roxy.upstream import breaker

ADMIN = Actor("admin", "owner", "127.0.0.1")
NEW_VALUE = TOKEN_PREFIX + "FINALREVIEWVALUE" + "D4" * 90
ORIGIN = "https://roxy.example"
PROBE_URL = "https://users.roblox.com/v1/users/authenticated"


class Notifier:
    """Records alerts; `site_origin` like the real notifier's (`ROXY_SITE_ORIGIN`)."""

    def __init__(self, site_origin: str = ORIGIN) -> None:
        self.alerts: list[Any] = []
        self.site_origin = site_origin

    def send(self, alert: Any) -> None:
        self.alerts.append(alert)


def manager(
    env: Any,
    dbs: Any,
    settings: Any,
    *,
    notifier: Notifier | None = None,
    worker: str = "w1",
    clock: Any | None = None,
    credentials_dir: Path | None = None,
) -> CredentialManager:
    return CredentialManager(
        credentials_dir=credentials_dir or env.credentials_dir,
        dbs=dbs,
        settings=settings,
        clock=clock or FakeClock(),
        worker_id=worker,
        encryption_key=load_encryption_key(env.credentials_dir),
        events=EventSink(lambda: notifier, lambda: None),
    )


def answer(status: int, body: bytes = b"") -> EgressResponse:
    return EgressResponse(status, httpx.Headers(), body, 1.0, 0, 0, Egress.CREDENTIAL, None, "HTTP/1.1")


def account(number: int) -> EgressResponse:
    return answer(200, json.dumps({"id": number, "name": "x"}).encode())


def fetch_of(*answers: EgressResponse) -> Any:
    queue = list(answers)

    async def fetch(url: str) -> EgressResponse:
        return queue.pop(0)

    return fetch


async def read_only(db: Any, on: bool) -> None:
    """Make `db`'s writer refuse every write (SQLITE_READONLY), as a read-only file or a full disk does."""
    if on:
        await db.write(lambda conn: None)  # the writer thread opens its connection with its first job
    writer = next(thread for thread in db._threads if thread.role == "writer")
    writer._conn.execute(f"PRAGMA query_only={1 if on else 0}")


async def attaches_cookie(m: CredentialManager) -> bool:
    request = httpx.Request("GET", PROBE_URL)
    try:
        await m.authorize(request, logical_url=request.url, probe=False)
    except CredentialUnavailable:
        return False
    return "cookie" in request.headers


def stored_meta(dbs: Any) -> dict[str, Any]:
    return dbs.control.read_sync(
        lambda conn: dict(conn.execute("SELECT * FROM credential_meta WHERE id = 1").fetchone())
    )


def stored_result(dbs: Any) -> dict[str, Any]:
    return dict(json.loads(stored_meta(dbs)["last_probe_result"] or "{}"))


# ============================================================================== probe verdicts (constraints-2)


async def test_a_rejection_of_the_old_value_never_rejects_the_replacement(env: Any, dbs: Any, settings: Any) -> None:
    """The reverse case of constraints-2: a 401 about the old value lands after a replace. It is the truth about
    the value that was sent, so the probe reports it, but the replacement is neither rejected nor alerted about."""
    notifier = Notifier()
    w1 = manager(env, dbs, settings, worker="w1")
    w2 = manager(env, dbs, settings, worker="w2", notifier=notifier)
    await w1.start()
    await w2.start()
    assert (await w1.probe("admin_check", fetch=fetch_of(account(1)))).outcome == "ok"

    async def replaced_meanwhile(url: str) -> EgressResponse:
        await w1.replace(NEW_VALUE, ADMIN, reason="a fresh cookie of the same account")
        return answer(401)

    landed = await w2.probe("liveness", fetch=replaced_meanwhile)
    assert landed.outcome == "rejected"
    assert notifier.alerts == []  # no "Token Expired" for a value nobody tried
    meta = stored_meta(dbs)
    assert (meta["fingerprint"], meta["status"]) == (w1.fingerprint_of(NEW_VALUE), "unknown")
    assert json.loads(meta["last_probe_result"])["result"] == "replaced"  # the new value's record is untouched


async def test_another_colors_status_never_describes_this_value(
    env: Any, dbs: Any, settings: Any, tmp_path: Path
) -> None:
    """Two colors with different bootstrap files: once the new color moved `credential_meta` to its own value, the
    old color's value has no status (it is not used for traffic) and its probes decide nothing."""
    old = manager(env, dbs, settings, worker="old")
    await old.start()
    assert (await old.probe("admin_check", fetch=fetch_of(account(7)))).outcome == "ok"
    assert old.available()
    other_dir = tmp_path / "new-color"
    shutil.copytree(env.credentials_dir, other_dir)
    other_value = TOKEN_PREFIX + "NEWCOLORFILE" + "E5" * 90
    (other_dir / "roblox_credential").write_text(other_value, encoding="utf-8")
    new = manager(env, dbs, settings, worker="new", credentials_dir=other_dir)
    await new.start()
    await old.refresh()
    assert old.status().status == "unknown"
    assert not old.available()
    assert not await attaches_cookie(old)
    assert (await old.probe("admin_check", fetch=fetch_of(account(7)))).outcome == "ok"  # true of the old file
    assert stored_meta(dbs)["status"] == "unknown"  # but it says nothing about the new color's value
    await new.refresh()
    assert new.status().status == "unknown"


# ======================================================================= unsaved rejections (constraints-3)


async def test_a_rejection_control_db_could_not_take_is_shared_once_it_can(env: Any, dbs: Any, settings: Any) -> None:
    clock = FakeClock()
    m = manager(env, dbs, settings, clock=clock)
    other = manager(env, dbs, settings, worker="w2", clock=clock)
    await m.start()
    await other.start()
    assert (await m.probe("admin_check", fetch=fetch_of(account(1)))).outcome == "ok"
    await read_only(dbs.control, True)
    try:
        assert (await m.probe("confirm_401", fetch=fetch_of(answer(401)))).outcome == "rejected"
        assert m.status().status == "rejected"
        assert m.status().last_probe_result == {"kind": "confirm_401", "result": "rejected_401", "status": 401}
        clock.advance(5)
        assert await m.refresh()  # control.db reads fine but takes no write: the rejection stays in force here
        assert not m.available()
    finally:
        await read_only(dbs.control, False)
    assert stored_meta(dbs)["status"] == "active"  # not shared yet
    clock.advance(5)
    await m.refresh()  # the first refresh that can write shares it
    assert stored_meta(dbs)["status"] == "rejected"
    await other.refresh()
    assert other.status().status == "rejected"
    assert m._pending_rejection is None


async def test_an_unsaved_rejection_of_a_replaced_value_is_moot(env: Any, dbs: Any, settings: Any) -> None:
    clock = FakeClock()
    m = manager(env, dbs, settings, clock=clock)
    await m.start()
    assert (await m.probe("admin_check", fetch=fetch_of(account(1)))).outcome == "ok"
    await read_only(dbs.control, True)
    try:
        assert (await m.probe("admin_check", fetch=fetch_of(account(2)))).outcome == ACCOUNT_MISMATCH
        assert m.status().status == "rejected"
    finally:
        await read_only(dbs.control, False)
    status = await m.replace(NEW_VALUE, ADMIN, reason="a fresh cookie")
    assert status.status == "unknown"  # the kept rejection was about the value the replace took over from
    clock.advance(5)
    await m.refresh()
    assert stored_meta(dbs)["status"] == "unknown"
    assert m._pending_rejection is None


# =============================================================== answers without an account id (constraints-4)


async def test_an_answer_without_an_account_never_confirms_a_recorded_account(
    env: Any, dbs: Any, settings: Any
) -> None:
    """A changed bootstrap file keeps the old account for comparison (C1). An HTML 200 cannot show which account
    the new file belongs to, so the value stays unconfirmed; an answer naming the same account confirms it."""
    first = manager(env, dbs, settings)
    await first.start()
    assert (await first.probe("admin_check", fetch=fetch_of(account(5)))).outcome == "ok"
    (env.credentials_dir / "roblox_credential").write_text(NEW_VALUE, encoding="utf-8")
    restarted = manager(env, dbs, settings, worker="w2")
    await restarted.start()
    assert restarted.status().status == "unknown"
    page = await restarted.probe("health", fetch=fetch_of(answer(200, b"<html>Just a moment</html>")))
    assert page.outcome == "ok_no_account_id"
    assert restarted.status().status == "unknown"
    assert not restarted.available()
    assert stored_result(dbs)["result"] == "ok_no_account_id"
    assert (await restarted.probe("admin_check", fetch=fetch_of(account(5)))).outcome == "ok"
    assert restarted.available()


async def test_an_answer_without_an_account_confirms_a_value_with_none_to_compare(
    env: Any, dbs: Any, settings: Any
) -> None:
    """A probe URL that never names an account still works for a value with no account recorded (unchanged), and an
    active value stays active when Roblox answers a liveness probe with a page."""
    m = manager(env, dbs, settings)
    await m.start()
    plain = await m.probe("admin_check", fetch=fetch_of(answer(200, b"<html>ok</html>")))
    assert plain.outcome == "ok_no_account_id"
    assert m.status().status == "active"
    assert (await m.probe("liveness", fetch=fetch_of(answer(200, b"not json")))).outcome == "ok_no_account_id"
    assert m.status().status == "active"


async def test_an_answer_without_an_account_keeps_a_401_rejection(env: Any, dbs: Any, settings: Any) -> None:
    m = manager(env, dbs, settings)
    await m.start()
    assert (await m.probe("admin_check", fetch=fetch_of(answer(401)))).outcome == "rejected"
    assert (await m.probe("admin_check", fetch=fetch_of(answer(200, b"<html/>")))).outcome == "ok_no_account_id"
    assert m.status().status == "rejected"


# ======================================================================== accounts after a replace (docs_a-1)


async def test_replace_compares_the_new_account_with_the_previous_one(env: Any, dbs: Any, settings: Any) -> None:
    m = manager(env, dbs, settings)
    await m.start()
    assert (await m.probe("admin_check", fetch=fetch_of(account(1)))).outcome == "ok"
    previous = m.status().account_id_fingerprint
    await m.replace(NEW_VALUE, ADMIN, reason="another account, on purpose")
    assert stored_result(dbs) == {"previous_account": previous, "result": "replaced"}
    timeout = await m.probe("admin_check", fetch=fetch_of(answer(503)))  # an answer that names nobody
    assert timeout.outcome == "http_503"
    assert stored_result(dbs)["previous_account"] == previous  # still waiting for the first account

    changed = await m.probe("admin_check", fetch=fetch_of(account(2)))
    assert (changed.outcome, changed.ok, changed.account_match) == ("ok", True, False)
    status = m.status()
    assert status.status == "active"  # the replace was the deliberate, confirmed switch (C1)
    assert status.account_id_fingerprint not in (None, previous)
    assert status.last_probe_result is not None
    assert status.last_probe_result["result"] == ACCOUNT_CHANGED
    assert status.last_probe_result["previous_account"] == previous

    again = await m.probe("liveness", fetch=fetch_of(account(2)))
    assert (again.outcome, again.account_match) == ("ok", True)
    assert stored_result(dbs) == {"kind": "liveness", "result": "ok", "status": 200}


async def test_replace_with_the_same_account_says_so(env: Any, dbs: Any, settings: Any) -> None:
    m = manager(env, dbs, settings)
    await m.start()
    assert (await m.probe("admin_check", fetch=fetch_of(account(9)))).outcome == "ok"
    await m.replace(NEW_VALUE, ADMIN, reason="renewed")
    renewed = await m.probe("admin_check", fetch=fetch_of(account(9)))
    assert (renewed.outcome, renewed.account_match) == ("ok", True)
    assert stored_result(dbs)["result"] == "ok"


# ============================================================================ the mismatch alert (docs_a-2)


async def test_the_rejection_alerts_say_what_happened(env: Any, dbs: Any, settings: Any) -> None:
    notifier = Notifier()
    m = manager(env, dbs, settings, notifier=notifier)
    await m.start()
    assert (await m.probe("admin_check", fetch=fetch_of(account(1)))).outcome == "ok"
    assert (await m.probe("admin_check", fetch=fetch_of(account(2)))).outcome == ACCOUNT_MISMATCH
    (switch,) = notifier.alerts
    assert switch.subject == "Token Expired"  # plan 17.7: v1's subject, owners filter on it
    assert "different Roblox account" in switch.summary
    assert "xpired" not in switch.summary
    assert switch.fields == {"status": "rejected", "result": ACCOUNT_MISMATCH}
    await m.confirm_account(ADMIN, reason="typed the C1 warning")
    assert (await m.probe("admin_check", fetch=fetch_of(answer(401)))).outcome == "rejected"
    expired = notifier.alerts[-1]
    assert expired.summary.startswith("An auth token has expired")


# ==================================================================================== alert links (brain-6)


def test_egress_alerts_link_their_card_and_runbook() -> None:
    notifier = Notifier()
    sink = EventSink(lambda: notifier, lambda: None)
    sink.alert(type="credential_rejected", severity="critical", subject="Token Expired", summary="s",
               page="credential#status")  # fmt: skip
    sink.alert(type="leak_guard", severity="critical", subject="x", summary="s", page="egress#trips")
    sink.alert(type="rotator_quota", severity="warn", subject="x", summary="s", page="egress#budget",
               link="https://elsewhere.example/a")  # fmt: skip
    sink.alert(type="not_in_the_catalog", severity="warn", subject="x", summary="s")
    rejected, leak, quota, unknown = notifier.alerts
    assert (rejected.link, rejected.runbook) == (f"{ORIGIN}/admin/credential#status", "credential-rejected")
    assert (leak.link, leak.runbook) == (f"{ORIGIN}/admin/egress#trips", "leak-guard")
    assert (quota.link, quota.runbook) == ("https://elsewhere.example/a", "rotator-quota")  # an explicit link wins
    assert (unknown.link, unknown.runbook) == (None, None)
    assert runbook_for("credential_rotated") == "credential-rotated"
    assert page_link(object(), "credential#replace") == "/admin/credential#replace"  # no origin configured
    assert page_link(notifier, None) is None
    assert EgressAlert("t", "warn", "s", "x", runbook="r").runbook == "r"


async def test_the_quota_alert_links_the_budget_card(env: Any, dbs: Any, settings: Any) -> None:
    notifier = Notifier()
    pool = make_pool(env, dbs, settings, notifier=notifier)
    settings.set("rotator_quota_gb_per_month", 0.001)  # 1,000,000 bytes
    seed_usage(dbs, int(FakeClock().now()) - 600, 600_000)
    await pool.start()
    (alert,) = notifier.alerts
    assert alert.type == "rotator_quota"
    assert (alert.link, alert.runbook) == (f"{ORIGIN}/admin/egress#budget", "rotator-quota")
    assert "page" not in alert.fields


# ============================================================================ rotator streak and billing


class FakeClient:
    async def aclose(self) -> None:
        return None


def make_pool(
    env: Any, dbs: Any, settings: Any, *, notifier: Notifier | None = None, clock: Any | None = None
) -> RotatorPool:
    return RotatorPool(
        credentials_dir=env.credentials_dir,
        dbs=dbs,
        settings=settings,
        clock=clock or FakeClock(),
        echo_url="http://127.0.0.1:9/ip",
        encryption_key=load_encryption_key(env.credentials_dir),
        client_factory=lambda url, session_id, keepalive: FakeClient(),
        events=EventSink(lambda: notifier, lambda: None),
    )


def seed_usage(dbs: Any, at_s: int, size: int) -> None:
    dbs.metrics.write_sync(
        lambda conn: conn.execute(
            "INSERT INTO egress_usage (bucket_start, egress, granularity, requests, req_bytes, resp_bytes, "
            "overhead_bytes) VALUES (?, 'rotator', 'minute', 1, ?, 0, 0)",
            (at_s - at_s % 60, size),
        )
    )


def reset_usage(dbs: Any) -> None:
    """What the Data page's Egress usage reset does to the statistics table."""
    dbs.metrics.write_sync(lambda conn: conn.execute("DELETE FROM egress_usage"))


def usage(at_ms: int, size: int) -> EgressUsage:
    return EgressUsage(at_ms, Egress.ROTATOR, "caller", "s", size, 0, 0, 1, "socket", 200)


async def test_the_streak_row_is_a_counter_never_an_open_breaker(env: Any, dbs: Any, settings: Any) -> None:
    """docs_a-10: the park is the `rotator:parked` cooldown; the streak row stays `closed`, so no breaker view reads
    it as half-open, before or after the park."""
    settings.set("rotator_max_failures", 3)
    clock = FakeClock()
    pool = make_pool(env, dbs, settings, clock=clock)
    await pool.start()
    for _ in range(3):
        await pool.record_result(False, "timeout")
    assert pool.availability()[1] == "rotator_parked"

    def row() -> breaker.BreakerRow | None:
        rows: dict[str, breaker.BreakerRow] = dbs.hot.read_sync(lambda conn: breaker.load(conn, [STREAK_KEY]))
        return rows.get(STREAK_KEY)

    parked = row()
    assert parked is not None
    assert (parked.state, parked.failures) == (breaker.BreakerState.CLOSED, 0)
    assert breaker.effective_state(parked, clock.now()) is breaker.BreakerState.CLOSED
    await pool.record_result(False, "timeout")
    await pool.record_result(True, "http_200")
    after = row()
    assert after is not None
    assert (after.state, after.failures) == (breaker.BreakerState.CLOSED, 0)


async def test_the_billing_count_survives_a_statistics_reset(env: Any, dbs: Any, settings: Any) -> None:
    """data-4: the hard stop holds after the usage statistics are reset, and new bytes add to what was billed."""
    clock = FakeClock()
    settings.set("rotator_quota_gb_per_month", 0.001)  # 1,000,000 bytes
    pool = make_pool(env, dbs, settings, clock=clock)
    seed_usage(dbs, int(clock.now()) - 600, 600_000)
    await pool.start()
    assert pool.usage_snapshot().cycle_bytes == 600_000
    reset_usage(dbs)
    await pool.refresh(force=True)
    assert pool.usage_snapshot().cycle_bytes == 600_000  # the floor
    pool.on_usage(usage(clock.now_ms(), 500_000), True)  # handed to the recorder, not in metrics.db yet
    after = pool.usage_snapshot()
    assert after.cycle_bytes == 600_000  # counted 500,000 and the floor 600,000: still a lower bound, never added
    assert not after.stopped
    await pool.refresh(force=True)
    stored = dbs.control.read_sync(read_billing)
    assert (stored.cycle_floor, stored.cycle_counted) == (600_000, 500_000)


async def test_counted_bytes_are_shared_fleet_wide_and_never_counted_twice(env: Any, dbs: Any, settings: Any) -> None:
    clock = FakeClock()
    settings.set("rotator_quota_gb_per_month", 0.001)
    pool_a = make_pool(env, dbs, settings, clock=clock)
    pool_b = make_pool(env, dbs, settings, clock=clock)
    await pool_a.start()
    await pool_b.start()
    pool_a.on_usage(usage(clock.now_ms(), 700_000), True)
    await pool_a.refresh(force=True)
    await pool_b.refresh(force=True)
    assert pool_b.usage_snapshot().cycle_bytes == 700_000  # worker A's bytes, before any recorder flush
    seed_usage(dbs, int(clock.now()), 700_000)  # the recorder flushed the same bytes
    await pool_b.refresh(force=True)
    assert pool_b.usage_snapshot().cycle_bytes == 700_000  # the largest lower bound, not their sum
    pool_b.on_usage(usage(clock.now_ms(), 400_000), False)  # the recorder could not take these
    await pool_b.refresh(force=True)
    reset_usage(dbs)
    await pool_a.refresh(force=True)
    stopped = pool_a.usage_snapshot()
    assert stopped.cycle_bytes == 1_100_000
    assert stopped.stop_reason == "rotator_quota_hard_stop"


async def test_the_billing_count_starts_again_with_the_next_cycle_and_day(env: Any, dbs: Any, settings: Any) -> None:
    clock = FakeClock()  # 2025-10-09 08:53 UTC: mid-cycle for billing day 1
    settings.set("rotator_billing_day", 1)
    pool = make_pool(env, dbs, settings, clock=clock)
    await pool.start()
    pool.on_usage(usage(clock.now_ms(), 250_000), True)
    await pool.refresh(force=True)
    assert (pool.usage_snapshot().cycle_bytes, pool.usage_snapshot().day_bytes) == (250_000, 250_000)
    first_cycle = cycle_start_for(clock.now(), 1)
    clock.advance(86_400)
    await pool.refresh(force=True)
    next_day = pool.usage_snapshot()
    assert next_day.cycle_start == first_cycle
    assert (next_day.cycle_bytes, next_day.day_bytes) == (250_000, 0)
    clock.advance(32 * 86_400)
    await pool.refresh(force=True)
    next_cycle = pool.usage_snapshot()
    assert next_cycle.cycle_start != first_cycle
    assert next_cycle.cycle_bytes == 0


def test_a_damaged_billing_row_counts_nothing(dbs: Any) -> None:
    def write(conn: Any) -> None:
        conn.execute(
            "INSERT INTO service_state (key, value_json, updated_at) VALUES (?, ?, 0)",
            (BILLING_KEY, '{"cycle_start": 5, "cycle_floor": NaN, "cycle_counted": Infinity, "day_floor": "x"}'),
        )

    dbs.control.write_sync(write)
    stored = dbs.control.read_sync(read_billing)
    assert stored == BillingCount(cycle_start=5)
    count = BillingCount(cycle_start=10, cycle_floor=900, cycle_counted=950, day_start=20, day_floor=30, day_counted=5)
    assert billed_bytes(1_000, 40, count, 10, 20) == (1_000, 40)
    assert billed_bytes(0, 0, count, 10, 20) == (950, 30)
    assert billed_bytes(0, 0, count, 11, 21) == (0, 0)  # another cycle and day: nothing carried over
    assert day_start_for(86_400 * 3 + 5) == 86_400 * 3


@pytest.mark.parametrize("handed_off", [True, False], ids=["recorder", "kept"])
async def test_a_refused_billing_write_keeps_the_bytes_for_the_next_refresh(
    env: Any, dbs: Any, settings: Any, handed_off: bool
) -> None:
    clock = FakeClock()
    pool = make_pool(env, dbs, settings, clock=clock)
    await pool.start()
    pool.on_usage(usage(clock.now_ms(), 123_000), handed_off)
    await read_only(dbs.control, True)
    try:
        await pool.refresh(force=True)
    finally:
        await read_only(dbs.control, False)
    assert dbs.control.read_sync(read_billing).cycle_counted == 0
    assert pool.usage_snapshot().cycle_bytes == 123_000
    await pool.refresh(force=True)
    assert dbs.control.read_sync(read_billing).cycle_counted == 123_000
    assert pool.usage_snapshot().cycle_bytes == 123_000
